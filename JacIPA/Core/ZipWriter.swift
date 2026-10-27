import Foundation

/// Écriture d'un ZIP simple (pas de zip64). Deux modes : stocké (on calcule le CRC)
/// ou copie brute d'une entrée existante (on garde méthode, CRC et tailles).
final class ZipWriter {
    private let handle: FileHandle
    private var central = Data()
    private var count: UInt32 = 0
    private var offset: UInt64 = 0

    init(url: URL) throws {
        try? FileManager.default.removeItem(at: url)
        guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
            throw JacIPAError.message("Impossible de créer \(url.lastPathComponent).")
        }
        handle = try FileHandle(forWritingTo: url)
    }

    func addStored(path: String, data: Data, externalAttributes: UInt32, dosTime: UInt16, dosDate: UInt16) throws {
        let crc = CRC32.checksum(data)
        try addRaw(path: path, method: 0, crc32: crc, compressed: data, uncompressedSize: UInt64(data.count),
                   externalAttributes: externalAttributes, dosTime: dosTime, dosDate: dosDate)
    }

    func addRaw(path: String, method: UInt16, crc32: UInt32, compressed: Data, uncompressedSize: UInt64,
                externalAttributes: UInt32, dosTime: UInt16, dosDate: UInt16) throws {
        guard offset < 0xFFFF_FFFF, compressed.count < 0xFFFF_FFFF, uncompressedSize < 0xFFFF_FFFF else {
            throw JacIPAError.message("IPA de plus de 4 Go : pas géré par JacIPA.")
        }
        guard count < 0xFFFF else {
            throw JacIPAError.message("Plus de 65 535 fichiers dans l'IPA : pas géré par JacIPA.")
        }
        let nameData = Data(path.utf8)
        guard nameData.count <= 0xFFFF else { throw JacIPAError.message("Nom de fichier trop long : \(path)") }

        var local = Data()
        local.appendU32(0x0403_4B50)
        local.appendU16(20)             // version needed
        local.appendU16(0x0800)         // flags : noms UTF-8
        local.appendU16(method)
        local.appendU16(dosTime)
        local.appendU16(dosDate)
        local.appendU32(crc32)
        local.appendU32(UInt32(compressed.count))
        local.appendU32(UInt32(uncompressedSize))
        local.appendU16(UInt16(nameData.count))
        local.appendU16(0)              // extra
        local.append(nameData)

        try handle.write(contentsOf: local)
        try handle.write(contentsOf: compressed)

        var c = Data()
        c.appendU32(0x0201_4B50)
        c.appendU16(0x031E)             // fait par : Unix, v3.0
        c.appendU16(20)
        c.appendU16(0x0800)
        c.appendU16(method)
        c.appendU16(dosTime)
        c.appendU16(dosDate)
        c.appendU32(crc32)
        c.appendU32(UInt32(compressed.count))
        c.appendU32(UInt32(uncompressedSize))
        c.appendU16(UInt16(nameData.count))
        c.appendU16(0)                  // extra
        c.appendU16(0)                  // commentaire
        c.appendU16(0)                  // disque
        c.appendU16(0)                  // attributs internes
        c.appendU32(externalAttributes)
        c.appendU32(UInt32(offset))
        c.append(nameData)
        central.append(c)

        offset += UInt64(local.count + compressed.count)
        count += 1
    }

    func finish() throws {
        guard central.count < 0xFFFF_FFFF, offset < 0xFFFF_FFFF else {
            throw JacIPAError.message("IPA de plus de 4 Go : pas géré par JacIPA.")
        }
        try handle.write(contentsOf: central)
        var e = Data()
        e.appendU32(0x0605_4B50)
        e.appendU16(0)
        e.appendU16(0)
        e.appendU16(UInt16(count))
        e.appendU16(UInt16(count))
        e.appendU32(UInt32(central.count))
        e.appendU32(UInt32(offset))
        e.appendU16(0)
        try handle.write(contentsOf: e)
        try handle.close()
    }
}
