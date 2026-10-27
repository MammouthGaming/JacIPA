import Foundation

/// Petits accès binaires. Tous les offsets sont relatifs au début logique de la Data
/// (on passe toujours par `startIndex`, donc ça marche aussi sur des tranches).
extension Data {
    /// Copie `count` octets à partir de `offset`. Tronque si on dépasse la fin.
    func copy(_ offset: Int, _ count: Int) -> Data {
        let start = startIndex + offset
        guard offset >= 0, count > 0, start < endIndex else { return Data() }
        let end = Swift.min(start + count, endIndex)
        return Data(self[start..<end])
    }

    func byte(_ offset: Int) -> UInt8 {
        self[startIndex + offset]
    }

    func u16(_ offset: Int) -> UInt16 {
        UInt16(byte(offset)) | UInt16(byte(offset + 1)) << 8
    }

    func u32(_ offset: Int) -> UInt32 {
        UInt32(byte(offset))
            | UInt32(byte(offset + 1)) << 8
            | UInt32(byte(offset + 2)) << 16
            | UInt32(byte(offset + 3)) << 24
    }

    func u64(_ offset: Int) -> UInt64 {
        UInt64(u32(offset)) | UInt64(u32(offset + 4)) << 32
    }

    func u32BE(_ offset: Int) -> UInt32 {
        UInt32(byte(offset)) << 24
            | UInt32(byte(offset + 1)) << 16
            | UInt32(byte(offset + 2)) << 8
            | UInt32(byte(offset + 3))
    }

    /// Chaîne C (terminée par 0) de longueur maximale `maxLength`.
    func cString(_ offset: Int, maxLength: Int) -> String {
        let chunk = copy(offset, maxLength)
        let bytes = chunk.prefix { $0 != 0 }
        return String(decoding: bytes, as: UTF8.self)
    }

    func ascii(_ offset: Int, _ count: Int) -> String {
        String(decoding: copy(offset, count), as: UTF8.self)
    }

    mutating func putU32(_ value: UInt32, at offset: Int) {
        let s = startIndex + offset
        self[s] = UInt8(value & 0xFF)
        self[s + 1] = UInt8((value >> 8) & 0xFF)
        self[s + 2] = UInt8((value >> 16) & 0xFF)
        self[s + 3] = UInt8((value >> 24) & 0xFF)
    }

    mutating func appendU16(_ value: UInt16) {
        append(UInt8(value & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
    }

    mutating func appendU32(_ value: UInt32) {
        appendU16(UInt16(value & 0xFFFF))
        appendU16(UInt16((value >> 16) & 0xFFFF))
    }
}

extension Int64 {
    var fileSizeText: String {
        ByteCountFormatter.string(fromByteCount: self, countStyle: .file)
    }
}
