import Foundation

struct TarEntry: Sendable {
    let path: String
    let typeFlag: UInt8
    let data: Data

    var isFile: Bool { typeFlag == 0 || typeFlag == UInt8(ascii: "0") || typeFlag == UInt8(ascii: "7") }
    var isDirectory: Bool { typeFlag == UInt8(ascii: "5") }
    var isSymlink: Bool { typeFlag == UInt8(ascii: "2") }
}

/// Lecteur tar : ustar, préfixe ustar, noms longs GNU (type L), en-têtes pax (type x).
enum TarArchive {
    static func parse(_ data: Data) throws -> [TarEntry] {
        var entries: [TarEntry] = []
        var offset = 0
        var longName: String?
        var paxPath: String?

        while offset + 512 <= data.count {
            let header = data.copy(offset, 512)
            if header.allSatisfy({ $0 == 0 }) { break }

            let size = parseSize(header, 124, 12)
            let typeFlag = header.byte(156)
            var name = header.cString(0, maxLength: 100)
            let prefix = header.cString(345, maxLength: 155)
            if !prefix.isEmpty, header.cString(257, maxLength: 6).hasPrefix("ustar") {
                name = prefix + "/" + name
            }
            offset += 512
            let content = data.copy(offset, size)
            offset += ((size + 511) / 512) * 512

            switch typeFlag {
            case UInt8(ascii: "L"):
                longName = content.cString(0, maxLength: content.count)
                continue
            case UInt8(ascii: "x"):
                paxPath = parsePax(content)["path"]
                continue
            case UInt8(ascii: "g"):
                continue
            default:
                break
            }

            if let p = paxPath {
                name = p
                paxPath = nil
            } else if let l = longName {
                name = l
                longName = nil
            }
            entries.append(TarEntry(path: name, typeFlag: typeFlag, data: content))
        }

        guard !entries.isEmpty else {
            throw JacIPAError.message("Archive tar vide ou illisible.")
        }
        return entries
    }

    private static func parseSize(_ d: Data, _ off: Int, _ len: Int) -> Int {
        let chunk = d.copy(off, len)
        if let first = chunk.first, first & 0x80 != 0 {
            // Encodage base-256 (fichiers > 8 Go)
            var value = 0
            for b in chunk.dropFirst() { value = (value << 8) | Int(b) }
            return value
        }
        let text = String(decoding: chunk.prefix { $0 != 0 }, as: UTF8.self)
            .trimmingCharacters(in: CharacterSet(charactersIn: " \0"))
        return Int(text, radix: 8) ?? 0
    }

    private static func parsePax(_ d: Data) -> [String: String] {
        var result: [String: String] = [:]
        let text = String(decoding: d, as: UTF8.self)
        for line in text.split(separator: "\n") {
            guard let space = line.firstIndex(of: " ") else { continue }
            let kv = line[line.index(after: space)...]
            guard let eq = kv.firstIndex(of: "=") else { continue }
            result[String(kv[..<eq])] = String(kv[kv.index(after: eq)...])
        }
        return result
    }
}
