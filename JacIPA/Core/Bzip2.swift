import Foundation

/// Décodeur bzip2 en Swift pur (Huffman + MTF + RLE2 + BWT inverse + RLE1).
/// Utilisé pour `data.tar.bz2` dans les vieux .deb. Les CRC ne sont pas vérifiés.
/// Supporte les flux concaténés (pbzip2). Logique validée contre le module `bz2` de Python via un port identique.
enum Bzip2Decoder {
    static func decode(_ data: Data) throws -> Data {
        let buf = [UInt8](data)
        var bits = Bits(buf)
        var out: [UInt8] = []
        out.reserveCapacity(min(buf.count * 4, 64 << 20))
        while !bits.atEnd {
            guard try bits.read(8) == 0x42, try bits.read(8) == 0x5A, try bits.read(8) == 0x68 else {
                throw berr("pas un flux bzip2")
            }
            let level = try bits.read(8) - 0x30
            guard (1 ... 9).contains(level) else { throw berr("niveau de bloc invalide") }
            while true {
                let magic = try bits.read(48)
                if magic == 0x3141_5926_5359 {
                    try decodeBlock(&bits, level, &out)
                } else if magic == 0x1772_4538_5090 {
                    _ = try bits.read(32) // CRC combiné
                    bits.align()
                    break
                } else {
                    throw berr("magic de bloc invalide")
                }
            }
        }
        return Data(out)
    }

    // MARK: - Flux de bits (MSB first)

    struct Bits {
        let buf: [UInt8]
        var pos = 0
        var bit = 0

        init(_ buf: [UInt8]) { self.buf = buf }

        var atEnd: Bool { pos >= buf.count }

        @inline(__always) mutating func read(_ n: Int) throws -> Int {
            var v = 0
            for _ in 0 ..< n {
                guard pos < buf.count else { throw berr("flux tronqué") }
                v = (v << 1) | ((Int(buf[pos]) >> (7 - bit)) & 1)
                bit += 1
                if bit == 8 { bit = 0; pos += 1 }
            }
            return v
        }

        mutating func align() {
            if bit != 0 { bit = 0; pos += 1 }
        }
    }

    // MARK: - Huffman canonique

    struct Huff {
        let minLen: Int
        let maxLen: Int
        var count: [Int]
        var start: [Int]
        var first: [Int]
        var perm: [Int]

        init(lengths: [Int]) throws {
            guard let mx = lengths.max(), let mn = lengths.filter({ $0 > 0 }).min() else { throw berr("table Huffman vide") }
            minLen = mn; maxLen = mx
            count = [Int](repeating: 0, count: mx + 2)
            start = [Int](repeating: 0, count: mx + 2)
            first = [Int](repeating: 0, count: mx + 2)
            perm = lengths.indices.sorted { a, b in
                lengths[a] != lengths[b] ? lengths[a] < lengths[b] : a < b
            }
            for l in lengths { count[l] += 1 }
            var pp = 0
            for l in 1 ... mx { start[l] = pp; pp += count[l] }
            var code = 0
            for l in 1 ... mx { first[l] = code; code = (code + count[l]) << 1 }
        }

        @inline(__always) func decode(_ bits: inout Bits) throws -> Int {
            var code = try bits.read(minLen)
            var l = minLen
            while true {
                let d = code - first[l]
                if d >= 0, d < count[l] { return perm[start[l] + d] }
                guard l < maxLen else { throw berr("code Huffman invalide") }
                let nb = try bits.read(1)
                code = (code << 1) | nb
                l += 1
            }
        }
    }

    // MARK: - Bloc

    private static func decodeBlock(_ bits: inout Bits, _ level: Int, _ out: inout [UInt8]) throws {
        _ = try bits.read(32) // CRC du bloc (non vérifié)
        if try bits.read(1) == 1 { throw berr("bloc « randomisé » : format obsolète non supporté") }
        let origPtr = try bits.read(24)

        // Carte des octets utilisés
        let usedGroups = try bits.read(16)
        var used: [UInt8] = []
        for g in 0 ..< 16 where usedGroups & (1 << (15 - g)) != 0 {
            let m = try bits.read(16)
            for j in 0 ..< 16 where m & (1 << (15 - j)) != 0 {
                used.append(UInt8(g * 16 + j))
            }
        }
        guard !used.isEmpty else { throw berr("table de symboles vide") }
        let alpha = used.count + 2

        // Sélecteurs (MTF)
        let ngroups = try bits.read(3)
        guard (2 ... 6).contains(ngroups) else { throw berr("nombre de groupes invalide") }
        let nsel = try bits.read(15)
        guard nsel > 0 else { throw berr("aucun sélecteur") }
        var mtfGroups = Array(0 ..< ngroups)
        var selectors: [Int] = []
        selectors.reserveCapacity(nsel)
        for _ in 0 ..< nsel {
            var j = 0
            while try bits.read(1) == 1 {
                j += 1
                guard j < ngroups else { throw berr("sélecteur invalide") }
            }
            let v = mtfGroups.remove(at: j)
            mtfGroups.insert(v, at: 0)
            selectors.append(v)
        }

        // Tables Huffman (longueurs delta-codées)
        var tables: [Huff] = []
        for _ in 0 ..< ngroups {
            var ln = try bits.read(5)
            var lengths: [Int] = []
            lengths.reserveCapacity(alpha)
            for _ in 0 ..< alpha {
                while true {
                    guard (1 ... 20).contains(ln) else { throw berr("longueur de code invalide") }
                    if try bits.read(1) == 0 { break }
                    let down = try bits.read(1) == 1
                    ln += down ? -1 : 1
                }
                lengths.append(ln)
            }
            tables.append(try Huff(lengths: lengths))
        }

        // Décodage Huffman → RLE2 + MTF inverse
        var mtf = used
        var block: [UInt8] = []
        let limit = 100_000 * level
        block.reserveCapacity(limit)
        var run = 0
        var runBit = 1
        var selIdx = 0
        var groupLeft = 0
        var table = tables[0]
        let eob = alpha - 1
        while true {
            if groupLeft == 0 {
                guard selIdx < nsel else { throw berr("sélecteurs épuisés") }
                table = tables[selectors[selIdx]]
                selIdx += 1
                groupLeft = 50
            }
            groupLeft -= 1
            let sym = try table.decode(&bits)
            if sym <= 1 { // RUNA / RUNB
                run += runBit << sym
                runBit <<= 1
                guard run <= limit else { throw berr("répétition trop longue") }
                continue
            }
            if run > 0 {
                guard block.count + run <= limit else { throw berr("bloc trop grand") }
                block.append(contentsOf: repeatElement(mtf[0], count: run))
                run = 0; runBit = 1
            }
            if sym == eob { break }
            let v = sym - 1
            let b = mtf.remove(at: v)
            mtf.insert(b, at: 0)
            guard block.count < limit else { throw berr("bloc trop grand") }
            block.append(b)
        }

        let n = block.count
        guard origPtr < n else { throw berr("origPtr invalide") }

        // BWT inverse
        var cftab = [Int](repeating: 0, count: 257)
        for b in block { cftab[Int(b) + 1] += 1 }
        for i in 0 ..< 256 { cftab[i + 1] += cftab[i] }
        var tt = [Int](repeating: 0, count: n)
        for (i, b) in block.enumerated() {
            tt[cftab[Int(b)]] = i
            cftab[Int(b)] += 1
        }

        // RLE1 : après 4 octets identiques, l'octet suivant est un compteur de répétitions
        var p = tt[origPtr]
        var last = -1
        var cnt = 0
        for _ in 0 ..< n {
            let b = block[p]
            p = tt[p]
            if cnt == 4 {
                out.append(contentsOf: repeatElement(UInt8(last), count: Int(b)))
                cnt = 0; last = -1
                continue
            }
            if Int(b) == last { cnt += 1 } else { last = Int(b); cnt = 1 }
            out.append(b)
        }
    }
}

private func berr(_ m: String) -> JacIPAError { .message("bzip2 : " + m) }
