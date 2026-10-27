import Foundation

/// Décodeur zstd (RFC 8878) en Swift pur, sans dictionnaire externe.
/// Utilisé pour `data.tar.zst` des .deb récents (dpkg ≥ 1.21). Le framework Compression d'Apple n'a pas zstd.
/// Structure volontairement proche du décodeur éducatif de zstd ; la logique a été validée
/// contre le binaire `zstd` 1.5 (niveaux 1 à 22, `--long`, multi-trames) via un port Python identique.
/// Les sommes de contrôle xxh64 ne sont pas vérifiées.
enum ZstdDecoder {
    static func decode(_ data: Data) throws -> Data {
        let buf = [UInt8](data)
        var pos = 0
        var out: [UInt8] = []
        out.reserveCapacity(min(buf.count * 4, 64 << 20))
        while pos < buf.count {
            guard pos + 4 <= buf.count else { throw zerr("flux tronqué") }
            let magic = le(buf, pos, 4); pos += 4
            if magic == 0xFD2F_B528 {
                pos = try decodeFrame(buf, pos, &out)
            } else if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
                guard pos + 4 <= buf.count else { throw zerr("trame ignorable tronquée") }
                let size = le(buf, pos, 4)
                pos += 4 + size
            } else {
                throw zerr("pas un flux zstd")
            }
        }
        return Data(out)
    }

    // MARK: - Trame et blocs

    private static func decodeFrame(_ buf: [UInt8], _ startPos: Int, _ out: inout [UInt8]) throws -> Int {
        var pos = startPos
        let fhd = try at(buf, pos, buf.count); pos += 1
        let fcsFlag = fhd >> 6
        let single = (fhd >> 5) & 1 == 1
        let checksum = (fhd >> 2) & 1 == 1
        let didFlag = fhd & 3
        if (fhd >> 3) & 1 == 1 { throw zerr("bit réservé dans l'en-tête") }
        if !single { pos += 1 } // Window descriptor : inutile, toute la sortie reste en mémoire
        let didSize = [0, 1, 2, 4][didFlag]
        guard pos + didSize <= buf.count else { throw zerr("en-tête tronqué") }
        let did = le(buf, pos, didSize); pos += didSize
        if did != 0 { throw zerr("flux avec dictionnaire externe : non supporté") }
        let fcsSize = [single ? 1 : 0, 2, 4, 8][fcsFlag]
        guard pos + fcsSize <= buf.count else { throw zerr("en-tête tronqué") }
        var fcs = le(buf, pos, fcsSize); pos += fcsSize
        if fcsSize == 2 { fcs += 256 }
        if fcsSize > 0, fcs > 1 << 31 { throw zerr("contenu trop gros (\(fcs) octets)") }
        if fcsSize > 0 { out.reserveCapacity(out.count + fcs) }

        var ctx = Ctx()
        let startLen = out.count
        while true {
            guard pos + 3 <= buf.count else { throw zerr("en-tête de bloc tronqué") }
            let bh = le(buf, pos, 3); pos += 3
            let last = bh & 1 == 1
            let btype = (bh >> 1) & 3
            let bsize = bh >> 3
            switch btype {
            case 0:
                guard pos + bsize <= buf.count else { throw zerr("bloc brut tronqué") }
                out.append(contentsOf: buf[pos ..< pos + bsize]); pos += bsize
            case 1:
                let b = try at(buf, pos, buf.count); pos += 1
                out.append(contentsOf: repeatElement(UInt8(b), count: bsize))
            case 2:
                guard pos + bsize <= buf.count else { throw zerr("bloc compressé tronqué") }
                try decodeBlock(buf, pos, pos + bsize, &ctx, &out); pos += bsize
            default:
                throw zerr("type de bloc réservé")
            }
            if last { break }
        }
        if checksum { pos += 4 }
        if fcsSize > 0, out.count - startLen != fcs { throw zerr("taille décompressée incohérente") }
        return pos
    }

    private struct Ctx {
        var huf: HufTable? = nil
        var ll: FSETable? = nil
        var of: FSETable? = nil
        var ml: FSETable? = nil
        var rep = [1, 4, 8]
    }

    private static func decodeBlock(_ buf: [UInt8], _ start: Int, _ end: Int, _ ctx: inout Ctx, _ out: inout [UInt8]) throws {
        var pos = start
        // --- Littéraux ---
        let b0 = try at(buf, pos, end)
        let ltype = b0 & 3
        let sf = (b0 >> 2) & 3
        var literals: [UInt8] = []
        var regen = 0
        if ltype <= 1 {
            if sf == 0 || sf == 2 {
                regen = b0 >> 3; pos += 1
            } else if sf == 1 {
                let b1 = try at(buf, pos + 1, end)
                regen = (b0 >> 4) | (b1 << 4); pos += 2
            } else {
                let b1 = try at(buf, pos + 1, end), b2 = try at(buf, pos + 2, end)
                regen = (b0 >> 4) | (b1 << 4) | (b2 << 12); pos += 3
            }
            if ltype == 0 {
                guard pos + regen <= end else { throw zerr("littéraux bruts tronqués") }
                literals = Array(buf[pos ..< pos + regen]); pos += regen
            } else {
                let b = try at(buf, pos, end); pos += 1
                literals = [UInt8](repeating: UInt8(b), count: regen)
            }
        } else {
            let hb: Int, streams: Int, sbits: Int
            switch sf {
            case 0: hb = 3; streams = 1; sbits = 10
            case 1: hb = 3; streams = 4; sbits = 10
            case 2: hb = 4; streams = 4; sbits = 14
            default: hb = 5; streams = 4; sbits = 18
            }
            guard pos + hb <= end else { throw zerr("en-tête de littéraux tronqué") }
            let h = le(buf, pos, hb); pos += hb
            regen = (h >> 4) & ((1 << sbits) - 1)
            let csize = (h >> (4 + sbits)) & ((1 << sbits) - 1)
            let litEnd = pos + csize
            guard litEnd <= end else { throw zerr("littéraux compressés tronqués") }
            if ltype == 2 {
                let (table, p) = try readHufTable(buf, pos, litEnd)
                ctx.huf = table; pos = p
            } else if ctx.huf == nil {
                throw zerr("littéraux sans arbre Huffman")
            }
            let table = ctx.huf!
            literals.reserveCapacity(regen)
            if streams == 1 {
                try hufDecodeStream(table, buf, pos, litEnd, regen, &literals)
            } else {
                guard pos + 6 <= litEnd else { throw zerr("table de sauts tronquée") }
                let s1 = le(buf, pos, 2), s2 = le(buf, pos + 2, 2), s3 = le(buf, pos + 4, 2)
                pos += 6
                let per = (regen + 3) >> 2
                let starts = [pos, pos + s1, pos + s1 + s2, pos + s1 + s2 + s3, litEnd]
                guard starts[3] <= litEnd else { throw zerr("tailles de flux Huffman invalides") }
                for k in 0 ..< 4 {
                    let cnt = k < 3 ? per : regen - 3 * per
                    guard cnt >= 0 else { throw zerr("taille de littéraux incohérente") }
                    try hufDecodeStream(table, buf, starts[k], starts[k + 1], cnt, &literals)
                }
            }
            pos = litEnd
        }
        guard literals.count == regen else { throw zerr("nombre de littéraux incohérent") }

        // --- Séquences ---
        let b = try at(buf, pos, end); pos += 1
        let nseq: Int
        if b == 0 {
            nseq = 0
        } else if b < 128 {
            nseq = b
        } else if b < 255 {
            let b1 = try at(buf, pos, end)
            nseq = ((b - 128) << 8) + b1; pos += 1
        } else {
            let b1 = try at(buf, pos, end), b2 = try at(buf, pos + 1, end)
            nseq = b1 + (b2 << 8) + 0x7F00; pos += 2
        }
        if nseq == 0 {
            out.append(contentsOf: literals)
            return
        }
        let modes = try at(buf, pos, end); pos += 1
        if modes & 3 != 0 { throw zerr("bits réservés dans les modes de séquences") }
        let (llT, p1) = try readSeqTable(buf, pos, end, (modes >> 6) & 3, Tables.llDefault, 6, 9, 36, ctx.ll)
        let (ofT, p2) = try readSeqTable(buf, p1, end, (modes >> 4) & 3, Tables.ofDefault, 5, 8, 32, ctx.of)
        let (mlT, p3) = try readSeqTable(buf, p2, end, (modes >> 2) & 3, Tables.mlDefault, 6, 9, 53, ctx.ml)
        ctx.ll = llT; ctx.of = ofT; ctx.ml = mlT
        pos = p3

        var bb = try BackBits(buf, pos, end)
        var sll = bb.read(llT.log)
        var sof = bb.read(ofT.log)
        var sml = bb.read(mlT.log)
        var litPos = 0

        for i in 0 ..< nseq {
            let ofCode = ofT.sym[sof]
            if ofCode > 31 { throw zerr("code d'offset invalide") }
            let ofVal = (1 << ofCode) + bb.read(ofCode)
            let mlCode = mlT.sym[sml]
            let ml = Tables.mlBase[mlCode] + bb.read(Tables.mlBits[mlCode])
            let llCode = llT.sym[sll]
            let ll = Tables.llBase[llCode] + bb.read(Tables.llBits[llCode])
            if i + 1 < nseq {
                sll = llT.base[sll] + bb.read(llT.nbits[sll])
                sml = mlT.base[sml] + bb.read(mlT.nbits[sml])
                sof = ofT.base[sof] + bb.read(ofT.nbits[sof])
            }

            // Offset réel et offsets répétés
            let offset: Int
            if ofVal > 3 {
                offset = ofVal - 3
                ctx.rep[2] = ctx.rep[1]; ctx.rep[1] = ctx.rep[0]; ctx.rep[0] = offset
            } else {
                var idx = ofVal
                if ll == 0 { idx += 1 }
                switch idx {
                case 1:
                    offset = ctx.rep[0]
                case 2:
                    offset = ctx.rep[1]; ctx.rep[1] = ctx.rep[0]; ctx.rep[0] = offset
                case 3:
                    offset = ctx.rep[2]; ctx.rep[2] = ctx.rep[1]; ctx.rep[1] = ctx.rep[0]; ctx.rep[0] = offset
                default:
                    offset = ctx.rep[0] - 1
                    if offset <= 0 { throw zerr("offset répété nul") }
                    ctx.rep[2] = ctx.rep[1]; ctx.rep[1] = ctx.rep[0]; ctx.rep[0] = offset
                }
            }

            // Exécution : littéraux puis copie (chevauchement possible → octet par octet)
            guard litPos + ll <= literals.count else { throw zerr("littéraux insuffisants") }
            if ll > 0 { out.append(contentsOf: literals[litPos ..< litPos + ll]); litPos += ll }
            guard offset <= out.count else { throw zerr("offset avant le début des données") }
            var src = out.count - offset
            for _ in 0 ..< ml {
                out.append(out[src]); src += 1
            }
        }
        if bb.overflowed { throw zerr("flux de séquences dépassé") }
        if litPos < literals.count { out.append(contentsOf: literals[litPos...]) }
    }

    private static func readSeqTable(_ buf: [UInt8], _ pos: Int, _ end: Int, _ mode: Int,
                                     _ defaults: [Int], _ defLog: Int, _ maxLog: Int, _ maxSym: Int,
                                     _ prev: FSETable?) throws -> (FSETable, Int) {
        switch mode {
        case 0:
            let table = try FSETable(freqs: defaults, log: defLog)
            return (table, pos)
        case 1:
            let s = try at(buf, pos, end)
            return (FSETable.rle(s), pos + 1)
        case 2:
            return try fseReadHeader(buf, pos, end, maxLog, maxSym)
        default:
            guard let prev else { throw zerr("mode « repeat » sans table précédente") }
            return (prev, pos)
        }
    }

    // MARK: - Flux de bits

    /// Flux lu à l'envers (FSE, Huffman) : commence au dernier octet, après le bit de padding.
    struct BackBits {
        let buf: [UInt8]
        let start: Int
        var bitpos: Int

        init(_ buf: [UInt8], _ start: Int, _ end: Int) throws {
            guard end > start, end <= buf.count else { throw zerr("flux de bits vide") }
            let last = Int(buf[end - 1])
            guard last != 0 else { throw zerr("padding de flux invalide") }
            self.buf = buf
            self.start = start
            bitpos = (end - start) * 8 - (8 - hsb(last))
        }

        var overflowed: Bool { bitpos < 0 }

        @inline(__always) mutating func read(_ n: Int) -> Int {
            if n == 0 { return 0 }
            bitpos -= n
            var bits = n
            var off = bitpos
            if bitpos < 0 { bits += bitpos; off = 0 }
            var v = 0
            if bits > 0 {
                let byte = off >> 3
                let shift = off & 7
                let nbytes = (shift + bits + 7) >> 3
                var acc = 0
                for i in 0 ..< nbytes { acc |= Int(buf[start + byte + i]) << (8 * i) }
                v = (acc >> shift) & ((1 << bits) - 1)
            }
            if bitpos < 0 { v <<= -bitpos }
            return v
        }
    }

    /// Flux lu à l'endroit, bits de poids faible d'abord (en-tête de table FSE).
    struct FwdBits {
        let buf: [UInt8]
        var pos: Int
        let end: Int
        var bit = 0

        init(_ buf: [UInt8], _ start: Int, _ end: Int) { self.buf = buf; pos = start; self.end = end }

        mutating func read(_ n: Int) throws -> Int {
            var v = 0
            for i in 0 ..< n {
                guard pos < end else { throw zerr("en-tête FSE tronqué") }
                v |= ((Int(buf[pos]) >> bit) & 1) << i
                bit += 1
                if bit == 8 { bit = 0; pos += 1 }
            }
            return v
        }

        mutating func rewind(_ n: Int) {
            for _ in 0 ..< n {
                if bit == 0 { bit = 7; pos -= 1 } else { bit -= 1 }
            }
        }

        mutating func align() -> Int {
            if bit != 0 { bit = 0; pos += 1 }
            return pos
        }
    }

    // MARK: - FSE

    struct FSETable {
        var log: Int
        var sym: [Int]
        var nbits: [Int]
        var base: [Int]

        init(freqs: [Int], log: Int) throws {
            let size = 1 << log
            self.log = log
            sym = [Int](repeating: 0, count: size)
            nbits = [Int](repeating: 0, count: size)
            base = [Int](repeating: 0, count: size)
            var high = size - 1
            var stateDesc = [Int](repeating: 0, count: freqs.count)
            for (i, f) in freqs.enumerated() {
                if f == -1 {
                    guard high >= 0 else { throw zerr("table FSE incohérente") }
                    sym[high] = i; high -= 1; stateDesc[i] = 1
                } else {
                    stateDesc[i] = f
                }
            }
            let step = (size >> 1) + (size >> 3) + 3
            let mask = size - 1
            var pos = 0
            for (i, f) in freqs.enumerated() where f > 0 {
                for _ in 0 ..< f {
                    sym[pos] = i
                    pos = (pos + step) & mask
                    while pos > high { pos = (pos + step) & mask }
                }
            }
            guard pos == 0 else { throw zerr("table FSE incohérente") }
            for i in 0 ..< size {
                let s = sym[i]
                let next = stateDesc[s]
                stateDesc[s] += 1
                let nb = log - hsb(next)
                nbits[i] = nb
                base[i] = (next << nb) - size
            }
        }

        private init(rleSymbol: Int) {
            log = 0; sym = [rleSymbol]; nbits = [0]; base = [0]
        }

        static func rle(_ symbol: Int) -> FSETable { FSETable(rleSymbol: symbol) }
    }

    /// Lit une distribution FSE. Retourne la table et la position après l'en-tête (alignée sur l'octet).
    private static func fseReadHeader(_ buf: [UInt8], _ start: Int, _ end: Int, _ maxLog: Int, _ maxSymbols: Int) throws -> (FSETable, Int) {
        var fb = FwdBits(buf, start, end)
        let log = try fb.read(4) + 5
        guard log <= maxLog else { throw zerr("accuracy log FSE trop grand") }
        var remaining = 1 << log
        var freqs: [Int] = []
        while remaining > 0, freqs.count < maxSymbols {
            let bits = hsb(remaining + 1) + 1
            var val = try fb.read(bits)
            let lowerMask = (1 << (bits - 1)) - 1
            let threshold = (1 << bits) - 1 - (remaining + 1)
            if (val & lowerMask) < threshold {
                fb.rewind(1); val &= lowerMask
            } else if val > lowerMask {
                val -= threshold
            }
            let proba = val - 1
            remaining -= proba < 0 ? -proba : proba
            freqs.append(proba)
            if proba == 0 {
                var rep = try fb.read(2)
                while rep == 3 {
                    freqs.append(contentsOf: [0, 0, 0])
                    rep = try fb.read(2)
                }
                for _ in 0 ..< rep { freqs.append(0) }
            }
        }
        guard remaining == 0, freqs.count <= maxSymbols else { throw zerr("distribution FSE invalide") }
        let pos = fb.align()
        let table = try FSETable(freqs: freqs, log: log)
        return (table, pos)
    }

    // MARK: - Huffman

    struct HufTable {
        let maxBits: Int
        var sym: [UInt8]
        var nbits: [Int]

        init(weights: [Int]) throws {
            var total = 0
            for w in weights where w > 0 { total += 1 << (w - 1) }
            guard total > 0, total & (total - 1) == 0 else { throw zerr("poids Huffman invalides") }
            let maxBits = hsb(total)
            guard maxBits <= 11 else { throw zerr("arbre Huffman trop profond") }
            self.maxBits = maxBits
            let size = 1 << maxBits
            sym = [UInt8](repeating: 0, count: size)
            nbits = [Int](repeating: 0, count: size)
            let bits = weights.map { $0 > 0 ? maxBits + 1 - $0 : 0 }
            var rankCount = [Int](repeating: 0, count: maxBits + 2)
            for b in bits where b > 0 { rankCount[b] += 1 }
            var rankIdx = [Int](repeating: 0, count: maxBits + 2)
            rankIdx[maxBits] = 0
            var i = maxBits
            while i > 0 {
                rankIdx[i - 1] = rankIdx[i] + rankCount[i] * (1 << (maxBits - i))
                i -= 1
            }
            for (s, b) in bits.enumerated() where b > 0 {
                let code = rankIdx[b]
                let len = 1 << (maxBits - b)
                for k in 0 ..< len {
                    sym[code + k] = UInt8(s)
                    nbits[code + k] = b
                }
                rankIdx[b] += len
            }
        }
    }

    /// Lit la description d'arbre Huffman (poids directs 4 bits ou compressés FSE). Retourne la table et la position après.
    private static func readHufTable(_ buf: [UInt8], _ start: Int, _ end: Int) throws -> (HufTable, Int) {
        let header = try at(buf, start, end)
        var pos = start + 1
        var weights: [Int] = []
        if header >= 128 {
            let n = header - 127
            guard pos + ((n + 1) >> 1) <= end else { throw zerr("poids Huffman tronqués") }
            for i in 0 ..< n {
                let b = Int(buf[pos + (i >> 1)])
                weights.append(i & 1 == 0 ? b >> 4 : b & 0xF)
            }
            pos += (n + 1) >> 1
        } else {
            let csize = header
            guard pos + csize <= end else { throw zerr("poids Huffman tronqués") }
            let (table, p2) = try fseReadHeader(buf, pos, pos + csize, 6, 256)
            var bb = try BackBits(buf, p2, pos + csize)
            var st1 = bb.read(table.log)
            var st2 = bb.read(table.log)
            while true {
                weights.append(table.sym[st1]); st1 = table.base[st1] + bb.read(table.nbits[st1])
                if bb.overflowed { weights.append(table.sym[st2]); break }
                weights.append(table.sym[st2]); st2 = table.base[st2] + bb.read(table.nbits[st2])
                if bb.overflowed { weights.append(table.sym[st1]); break }
                if weights.count > 255 { throw zerr("trop de poids Huffman") }
            }
            pos += csize
        }
        guard weights.count <= 255 else { throw zerr("trop de poids Huffman") }
        var total = 0
        for w in weights where w > 0 { total += 1 << (w - 1) }
        guard total > 0 else { throw zerr("poids Huffman nuls") }
        // Le dernier poids complète la somme à la puissance de 2 juste au-dessus.
        let next = 1 << (hsb(total) + 1)
        let left = next - total
        guard left & (left - 1) == 0 else { throw zerr("poids Huffman : reste non puissance de 2") }
        weights.append(hsb(left) + 1)
        let table = try HufTable(weights: weights)
        return (table, pos)
    }

    private static func hufDecodeStream(_ table: HufTable, _ buf: [UInt8], _ start: Int, _ end: Int, _ count: Int, _ out: inout [UInt8]) throws {
        if count == 0 { return }
        var bb = try BackBits(buf, start, end)
        let mask = (1 << table.maxBits) - 1
        var state = bb.read(table.maxBits)
        for _ in 0 ..< count {
            out.append(table.sym[state])
            let nb = table.nbits[state]
            state = ((state << nb) | bb.read(nb)) & mask
        }
    }

    // MARK: - Tables de codes (RFC 8878 §3.1.1.3.2)

    enum Tables {
        static let llBase: [Int] = Array(0 ..< 16) + [16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        static let llBits: [Int] = [Int](repeating: 0, count: 16) + [1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        static let mlBase: [Int] = (0 ..< 32).map { $0 + 3 } + [35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539]
        static let mlBits: [Int] = [Int](repeating: 0, count: 32) + [1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        static let llDefault: [Int] = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1]
        static let mlDefault: [Int] = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1]
        static let ofDefault: [Int] = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]
    }

    // MARK: - Utilitaires

    @inline(__always) static func le(_ buf: [UInt8], _ pos: Int, _ n: Int) -> Int {
        var v = 0
        for i in 0 ..< n { v |= Int(buf[pos + i]) << (8 * i) }
        return v
    }

    @inline(__always) static func at(_ buf: [UInt8], _ i: Int, _ end: Int) throws -> Int {
        guard i >= 0, i < end, i < buf.count else { throw zerr("données tronquées") }
        return Int(buf[i])
    }
}

private func zerr(_ m: String) -> JacIPAError { .message("zstd : " + m) }

/// Index du bit de poids fort (-1 pour 0).
@inline(__always) private func hsb(_ x: Int) -> Int { Int.bitWidth - 1 - x.leadingZeroBitCount }
