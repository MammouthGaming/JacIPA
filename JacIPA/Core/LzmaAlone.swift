import Foundation

/// Décodeur LZMA 1 (format « .lzma alone », utilisé par dpkg pour `data.tar.lzma`).
/// Port en Swift pur du décodeur de référence du LZMA SDK (LzmaSpec.cpp, Igor Pavlov, domaine public).
/// Le framework Compression d'Apple ne lit que le conteneur xz (LZMA2), d'où ce décodeur maison.
///
/// En-tête (13 octets) : 1 octet de propriétés (lc/lp/pb), taille du dictionnaire (UInt32 LE),
/// taille décompressée (UInt64 LE, 0xFFFF_FFFF_FFFF_FFFF = inconnue → marqueur de fin obligatoire).
enum LzmaAloneDecoder {
    static func decode(_ data: Data) throws -> Data {
        let bytes = [UInt8](data)
        guard bytes.count >= 13 else { throw JacIPAError.message("Flux .lzma tronqué (en-tête incomplet).") }

        var d = Int(bytes[0])
        guard d < 9 * 5 * 5 else { throw JacIPAError.message("En-tête .lzma invalide (propriétés).") }
        let lc = d % 9; d /= 9
        let lp = d % 5
        let pb = d / 5

        var dictSize: UInt32 = 0
        for i in 0..<4 { dictSize |= UInt32(bytes[1 + i]) << (8 * UInt32(i)) }
        if dictSize < 4096 { dictSize = 4096 }

        var unpackSize: UInt64 = 0
        for i in 0..<8 { unpackSize |= UInt64(bytes[5 + i]) << (8 * UInt64(i)) }
        let sizeDefined = unpackSize != UInt64.max
        if sizeDefined, unpackSize > 1 << 31 {
            throw JacIPAError.message("Flux .lzma trop gros (\(unpackSize) octets).")
        }

        var decoder = try Decoder(input: bytes, start: 13, lc: lc, lp: lp, pb: pb, dictSize: dictSize)
        let out = try decoder.run(unpackSize: sizeDefined ? Int(unpackSize) : nil)
        return Data(out)
    }

    // MARK: - Décodeur

    /// Toutes les probabilités vivent dans un seul tableau `probs`, adressé par offsets
    /// (comme LzmaDec.c) : ça évite les accès `inout` croisés sur `self` que Swift refuse.
    private struct Decoder {
        static let kNumBitModelTotalBits: UInt32 = 11
        static let kBitModelTotal: UInt16 = 1 << 11
        static let kNumMoveBits: UInt16 = 5
        static let kTopValue: UInt32 = 1 << 24
        static let kNumPosBitsMax = 4
        static let kNumStates = 12
        static let kNumLenToPosStates = 4
        static let kNumAlignBits = 4
        static let kEndPosModelIndex = 14
        static let kNumFullDistances = 1 << (kEndPosModelIndex >> 1) // 128
        static let kMatchMinLen = 2
        static let probInit: UInt16 = kBitModelTotal >> 1 // 1024

        // Offsets dans `probs`
        static let oIsMatch = 0
        static let oIsRep = oIsMatch + (kNumStates << kNumPosBitsMax)
        static let oIsRepG0 = oIsRep + kNumStates
        static let oIsRepG1 = oIsRepG0 + kNumStates
        static let oIsRepG2 = oIsRepG1 + kNumStates
        static let oIsRep0Long = oIsRepG2 + kNumStates
        static let oPosSlot = oIsRep0Long + (kNumStates << kNumPosBitsMax)
        static let oPosDecoders = oPosSlot + (kNumLenToPosStates << 6)
        static let oAlign = oPosDecoders + (1 + kNumFullDistances - kEndPosModelIndex)
        static let oLen = oAlign + (1 << kNumAlignBits)
        static let lenCoderSize = 2 + (16 << 3) + (16 << 3) + 256   // choice, choice2, low, mid, high
        static let oRepLen = oLen + lenCoderSize
        static let oLiteral = oRepLen + lenCoderSize
        // Dans un LenDecoder :
        static let lChoice = 0, lChoice2 = 1, lLow = 2, lMid = 2 + (16 << 3), lHigh = 2 + (16 << 3) + (16 << 3)

        // Entrée / codeur de plage
        let input: [UInt8]
        var pos: Int
        var range: UInt32 = 0xFFFF_FFFF
        var code: UInt32 = 0
        var corrupted = false

        let lc: Int, lp: Int, pb: Int
        let dictSize: UInt32

        var probs: [UInt16]
        /// Sortie complète en mémoire : elle sert aussi de dictionnaire.
        var out: [UInt8] = []

        init(input: [UInt8], start: Int, lc: Int, lp: Int, pb: Int, dictSize: UInt32) throws {
            self.input = input
            self.pos = start
            self.lc = lc; self.lp = lp; self.pb = pb
            self.dictSize = dictSize
            probs = [UInt16](repeating: Decoder.probInit, count: Decoder.oLiteral + (0x300 << (lc + lp)))

            // Init du codeur de plage : premier octet toujours 0, puis 4 octets big-endian.
            guard start + 5 <= input.count else { throw JacIPAError.message("Flux .lzma tronqué.") }
            guard input[start] == 0 else { throw JacIPAError.message("Flux .lzma corrompu (octet initial).") }
            pos += 1
            for _ in 0..<4 { code = (code << 8) | UInt32(nextByte()) }
            if code == range { throw JacIPAError.message("Flux .lzma corrompu (init).") }
        }

        // MARK: Codeur de plage

        @inline(__always) mutating func nextByte() -> UInt8 {
            if pos < input.count { let b = input[pos]; pos += 1; return b }
            corrupted = true // lecture au-delà de la fin
            return 0
        }

        @inline(__always) mutating func normalize() {
            if range < Decoder.kTopValue {
                range <<= 8
                code = (code << 8) | UInt32(nextByte())
            }
        }

        @inline(__always) mutating func decodeBit(_ i: Int) -> UInt32 {
            var p = probs[i]
            let bound = (range >> Decoder.kNumBitModelTotalBits) &* UInt32(p)
            let symbol: UInt32
            if code < bound {
                p &+= (Decoder.kBitModelTotal &- p) >> Decoder.kNumMoveBits
                range = bound
                symbol = 0
            } else {
                p &-= p >> Decoder.kNumMoveBits
                code &-= bound
                range &-= bound
                symbol = 1
            }
            probs[i] = p
            normalize()
            return symbol
        }

        mutating func decodeDirectBits(_ numBits: Int) -> UInt32 {
            var res: UInt32 = 0
            for _ in 0..<numBits {
                range >>= 1
                code &-= range
                let t = 0 &- (code >> 31)
                code &+= range & t
                if code == range { corrupted = true }
                normalize()
                res = (res << 1) &+ (t &+ 1)
            }
            return res
        }

        /// Arbre binaire direct sur probs[offset ..< offset + (1 << numBits)].
        mutating func bitTreeDecode(offset: Int, numBits: Int) -> UInt32 {
            var m: UInt32 = 1
            for _ in 0..<numBits {
                m = (m << 1) &+ decodeBit(offset + Int(m))
            }
            return m &- (1 << UInt32(numBits))
        }

        /// Arbre binaire inversé (bits de poids faible en premier).
        mutating func bitTreeReverseDecode(offset: Int, numBits: Int) -> UInt32 {
            var m: UInt32 = 1
            var sym: UInt32 = 0
            for i in 0..<numBits {
                let bit = decodeBit(offset + Int(m))
                m = (m << 1) &+ bit
                sym |= bit << UInt32(i)
            }
            return sym
        }

        // MARK: Longueurs et distances

        mutating func decodeLen(base: Int, posState: Int) -> Int {
            if decodeBit(base + Decoder.lChoice) == 0 {
                return Int(bitTreeDecode(offset: base + Decoder.lLow + (posState << 3), numBits: 3))
            }
            if decodeBit(base + Decoder.lChoice2) == 0 {
                return 8 + Int(bitTreeDecode(offset: base + Decoder.lMid + (posState << 3), numBits: 3))
            }
            return 16 + Int(bitTreeDecode(offset: base + Decoder.lHigh, numBits: 8))
        }

        mutating func decodeDistance(len: Int) -> UInt32 {
            let lenState = min(len, Decoder.kNumLenToPosStates - 1)
            let slot = Int(bitTreeDecode(offset: Decoder.oPosSlot + (lenState << 6), numBits: 6))
            if slot < 4 { return UInt32(slot) }
            let numDirectBits = (slot >> 1) - 1
            var dist = UInt32(2 | (slot & 1)) << UInt32(numDirectBits)
            if slot < Decoder.kEndPosModelIndex {
                // SDK : BitTreeReverseDecode(PosDecoders + dist - posSlot, numDirectBits)
                let offset = Decoder.oPosDecoders + Int(dist) - slot
                dist &+= bitTreeReverseDecode(offset: offset, numBits: numDirectBits)
            } else {
                dist &+= decodeDirectBits(numDirectBits - Decoder.kNumAlignBits) << UInt32(Decoder.kNumAlignBits)
                dist &+= bitTreeReverseDecode(offset: Decoder.oAlign, numBits: Decoder.kNumAlignBits)
            }
            return dist
        }

        // MARK: Littéraux

        mutating func decodeLiteral(state: Int, rep0: UInt32) {
            let prevByte: UInt32 = out.isEmpty ? 0 : UInt32(out[out.count - 1])
            var symbol: UInt32 = 1
            let litState = ((UInt32(out.count) & ((1 << UInt32(lp)) - 1)) << UInt32(lc)) + (prevByte >> UInt32(8 - lc))
            let base = Decoder.oLiteral + 0x300 * Int(litState)
            if state >= 7 {
                var matchByte = UInt32(out[out.count - Int(rep0) - 1])
                repeat {
                    let matchBit = (matchByte >> 7) & 1
                    matchByte <<= 1
                    let bit = decodeBit(base + Int(((1 + matchBit) << 8) + symbol))
                    symbol = (symbol << 1) | bit
                    if matchBit != bit { break }
                } while symbol < 0x100
            }
            while symbol < 0x100 {
                symbol = (symbol << 1) | decodeBit(base + Int(symbol))
            }
            out.append(UInt8(truncatingIfNeeded: symbol - 0x100))
        }

        // MARK: Boucle principale

        mutating func run(unpackSize: Int?) throws -> [UInt8] {
            out.reserveCapacity(unpackSize ?? min(input.count * 4, 64 << 20))

            var remaining = unpackSize
            var state = 0
            var rep0: UInt32 = 0, rep1: UInt32 = 0, rep2: UInt32 = 0, rep3: UInt32 = 0
            let pbMask = (1 << pb) - 1

            while true {
                if corrupted { throw JacIPAError.message("Flux .lzma corrompu ou tronqué.") }
                // Taille atteinte et codeur propre : terminé (le marqueur de fin est facultatif).
                if remaining == 0, code == 0 { return out }

                let posState = out.count & pbMask

                if decodeBit(Decoder.oIsMatch + (state << Decoder.kNumPosBitsMax) + posState) == 0 {
                    if remaining == 0 { throw JacIPAError.message("Flux .lzma : données au-delà de la taille annoncée.") }
                    decodeLiteral(state: state, rep0: rep0)
                    state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6)
                    if remaining != nil { remaining! -= 1 }
                    continue
                }

                var len: Int
                if decodeBit(Decoder.oIsRep + state) != 0 {
                    if remaining == 0 { throw JacIPAError.message("Flux .lzma : données au-delà de la taille annoncée.") }
                    if out.isEmpty { throw JacIPAError.message("Flux .lzma corrompu (répétition sans historique).") }
                    if decodeBit(Decoder.oIsRepG0 + state) == 0 {
                        if decodeBit(Decoder.oIsRep0Long + (state << Decoder.kNumPosBitsMax) + posState) == 0 {
                            // Short rep : un seul octet à distance rep0
                            state = state < 7 ? 9 : 11
                            out.append(out[out.count - Int(rep0) - 1])
                            if remaining != nil { remaining! -= 1 }
                            continue
                        }
                    } else {
                        let dist: UInt32
                        if decodeBit(Decoder.oIsRepG1 + state) == 0 {
                            dist = rep1
                        } else {
                            if decodeBit(Decoder.oIsRepG2 + state) == 0 {
                                dist = rep2
                            } else {
                                dist = rep3
                                rep3 = rep2
                            }
                            rep2 = rep1
                        }
                        rep1 = rep0
                        rep0 = dist
                    }
                    len = decodeLen(base: Decoder.oRepLen, posState: posState)
                    state = state < 7 ? 8 : 11
                } else {
                    rep3 = rep2; rep2 = rep1; rep1 = rep0
                    len = decodeLen(base: Decoder.oLen, posState: posState)
                    state = state < 7 ? 7 : 10
                    rep0 = decodeDistance(len: len)
                    if rep0 == 0xFFFF_FFFF {
                        // Marqueur de fin
                        if code == 0 { return out }
                        throw JacIPAError.message("Flux .lzma corrompu (marqueur de fin).")
                    }
                    if remaining == 0 { throw JacIPAError.message("Flux .lzma : données au-delà de la taille annoncée.") }
                    if rep0 >= dictSize || Int(rep0) >= out.count {
                        throw JacIPAError.message("Flux .lzma corrompu (distance invalide).")
                    }
                }

                len += Decoder.kMatchMinLen
                var isError = false
                if let r = remaining, r < len { len = r; isError = true }

                // Copie de la correspondance : peut se chevaucher, donc octet par octet.
                var src = out.count - Int(rep0) - 1
                for _ in 0..<len {
                    out.append(out[src])
                    src += 1
                }
                if remaining != nil { remaining! -= len }
                if isError { throw JacIPAError.message("Flux .lzma : correspondance au-delà de la taille annoncée.") }
            }
        }
    }
}
