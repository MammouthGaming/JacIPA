import Foundation

/// Un .deb est une archive « ar » : debian-binary, control.tar.*, data.tar.*
struct ArMember: Sendable {
    let name: String
    let data: Data
}

enum ArArchive {
    static func parse(_ data: Data) throws -> [ArMember] {
        guard data.count > 68, data.ascii(0, 8) == "!<arch>\n" else {
            throw JacIPAError.message("Ce fichier n'est pas un .deb (en-tête « ar » absent).")
        }
        var members: [ArMember] = []
        var offset = 8
        while offset + 60 <= data.count {
            var name = data.ascii(offset, 16).trimmingCharacters(in: .whitespaces)
            let sizeText = data.ascii(offset + 48, 10).trimmingCharacters(in: .whitespaces)
            guard let size = Int(sizeText), size >= 0 else {
                throw JacIPAError.message("En-tête « ar » corrompu dans ce .deb.")
            }
            offset += 60
            if name.hasSuffix("/") { name.removeLast() }
            members.append(ArMember(name: name, data: data.copy(offset, size)))
            offset += size + (size % 2)
        }
        return members
    }
}
