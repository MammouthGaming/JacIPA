import Foundation
import Compression

struct ZipEntry: Sendable, Hashable {
    let name: String
    let method: UInt16
    let crc32: UInt32
    let compressedSize: UInt64
    let uncompressedSize: UInt64
    let localHeaderOffset: UInt64
    let externalAttributes: UInt32
    let dosTime: UInt16
    let dosDate: UInt16

    var isDirectory: Bool { name.hasSuffix("/") }
    var unixMode: UInt16 { UInt16(truncatingIfNeeded: externalAttributes >> 16) }
    var isSymlink: Bool { (unixMode & 0xF000) == 0xA000 }
}

/// Lecture d'un ZIP (IPA) : répertoire central, zip64, méthodes 0 (stocké) et 8 (deflate).
final class ZipReader {
    let data: Data
    private(set) var entries: [ZipEntry] = []
    private var byName: [String: ZipEntry] = [:]

    convenience init(url: URL) throws {
        let data = try Data(contentsOf: url, options: .alwaysMapped)
        try self.init(data: data)
    }

    init(data: Data) throws {
        self.data = data
        try parseCentralDirectory()
    }

    func entry(named name: String) -> ZipEntry? {
        byName[name]
    }

    func entries(withPrefix prefix: String) -> [ZipEntry] {
        entries.filter { $0.name.hasPrefix(prefix) }
    }

    private func parseCentralDirectory() throws {
        let n = data.count
        guard n >= 22 else { throw JacIPAError.message("Fichier trop petit pour être un ZIP / IPA.") }

        // End of central directory : on remonte depuis la fin (commentaire possible).
        let minPos = max(0, n - 22 - 65535)
        var eocd = -1
        var i = n - 22
        while i >= minPos {
            if data.u32(i) == 0x0605_4B50 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw JacIPAError.message("Ce fichier n'est pas un ZIP / IPA valide.") }

        var total = UInt64(data.u16(eocd + 10))
        var cdSize = UInt64(data.u32(eocd + 12))
        var cdOffset = UInt64(data.u32(eocd + 16))

        if total == 0xFFFF || cdSize == 0xFFFF_FFFF || cdOffset == 0xFFFF_FFFF {
            let locator = eocd - 20
            guard locator >= 0, data.u32(locator) == 0x0706_4B50 else {
                throw JacIPAError.message("ZIP64 : localisateur manquant.")
            }
            let z64 = Int(data.u64(locator + 8))
            guard z64 >= 0, z64 + 56 <= n, data.u32(z64) == 0x0606_4B50 else {
                throw JacIPAError.message("ZIP64 : enregistrement de fin invalide.")
            }
            total = data.u64(z64 + 32)
            cdSize = data.u64(z64 + 40)
            cdOffset = data.u64(z64 + 48)
        }

        var off = Int(cdOffset)
        var list: [ZipEntry] = []
        list.reserveCapacity(Int(min(total, 200_000)))

        for _ in 0..<Int(total) {
            guard off + 46 <= n, data.u32(off) == 0x0201_4B50 else {
                throw JacIPAError.message("Répertoire central ZIP corrompu.")
            }
            let method = data.u16(off + 10)
            let dosTime = data.u16(off + 12)
            let dosDate = data.u16(off + 14)
            let crc = data.u32(off + 16)
            var comp = UInt64(data.u32(off + 20))
            var uncomp = UInt64(data.u32(off + 24))
            let nameLen = Int(data.u16(off + 28))
            let extraLen = Int(data.u16(off + 30))
            let commentLen = Int(data.u16(off + 32))
            let external = data.u32(off + 38)
            var local = UInt64(data.u32(off + 42))
            let name = String(decoding: data.copy(off + 46, nameLen), as: UTF8.self)

            // Champ extra zip64 (id 0x0001)
            var e = off + 46 + nameLen
            let extraEnd = e + extraLen
            while e + 4 <= extraEnd {
                let id = data.u16(e)
                let size = Int(data.u16(e + 2))
                var p = e + 4
                let fieldEnd = min(p + size, extraEnd)
                if id == 0x0001 {
                    if uncomp == 0xFFFF_FFFF, p + 8 <= fieldEnd { uncomp = data.u64(p); p += 8 }
                    if comp == 0xFFFF_FFFF, p + 8 <= fieldEnd { comp = data.u64(p); p += 8 }
                    if local == 0xFFFF_FFFF, p + 8 <= fieldEnd { local = data.u64(p); p += 8 }
                }
                e += 4 + size
            }

            list.append(ZipEntry(name: name, method: method, crc32: crc, compressedSize: comp,
                                 uncompressedSize: uncomp, localHeaderOffset: local,
                                 externalAttributes: external, dosTime: dosTime, dosDate: dosDate))
            off += 46 + nameLen + extraLen + commentLen
        }

        entries = list
        byName = Dictionary(list.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// Octets compressés tels quels (pour recopier sans recompresser).
    func rawCompressedData(of entry: ZipEntry) throws -> Data {
        let local = Int(entry.localHeaderOffset)
        guard local >= 0, local + 30 <= data.count, data.u32(local) == 0x0403_4B50 else {
            throw JacIPAError.message("En-tête local ZIP invalide pour \(entry.name).")
        }
        let nameLen = Int(data.u16(local + 26))
        let extraLen = Int(data.u16(local + 28))
        let start = local + 30 + nameLen + extraLen
        guard start + Int(entry.compressedSize) <= data.count else {
            throw JacIPAError.message("Données tronquées pour \(entry.name).")
        }
        return data.copy(start, Int(entry.compressedSize))
    }

    /// Contenu décompressé. `maxBytes` permet de ne lire que le début (en-têtes Mach-O).
    func read(_ entry: ZipEntry, maxBytes: Int? = nil) throws -> Data {
        let raw = try rawCompressedData(of: entry)
        switch entry.method {
        case 0:
            if let maxBytes, raw.count > maxBytes { return Data(raw.prefix(maxBytes)) }
            return raw
        case 8:
            return try Decompressor.decode(raw, algorithm: COMPRESSION_ZLIB, maxOutput: maxBytes)
        default:
            throw JacIPAError.message("Méthode de compression ZIP \(entry.method) non gérée (\(entry.name)).")
        }
    }
}
