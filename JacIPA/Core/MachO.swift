import Foundation

struct MachODylibRef: Sendable, Hashable {
    let path: String
    let weak: Bool
    let index: Int

    var fileName: String { (path as NSString).lastPathComponent }
}

struct MachOSlice: Sendable {
    let offset: Int
    let size: Int
    let is64: Bool
    let cpuType: UInt32
    let ncmds: Int
    let sizeofcmds: Int
    /// nil = pas de LC_ENCRYPTION_INFO (binaire jamais passé par l'App Store, ou dylib)
    let cryptid: UInt32?
    let dylibs: [MachODylibRef]

    var arch: String {
        switch cpuType {
        case 0x0100_000C: return "arm64"
        case 0x0000_000C: return "armv7"
        case 0x0100_0007: return "x86_64"
        default: return String(format: "cpu 0x%X", cpuType)
        }
    }

    var encrypted: Bool? { cryptid.map { $0 != 0 } }

    var headerSize: Int { is64 ? 32 : 28 }
    /// Début des commandes de chargement (absolu dans le fichier).
    var commandsStart: Int { offset + headerSize }
    /// Fin des commandes de chargement (absolu dans le fichier).
    var commandsEnd: Int { commandsStart + sizeofcmds }
}

/// Lecture (et petits patchs) des en-têtes Mach-O : fat ou thin, 32 ou 64 bits.
enum MachO {
    static let magic64: UInt32 = 0xFEED_FACF
    static let magic32: UInt32 = 0xFEED_FACE
    static let fatMagic: UInt32 = 0xCAFE_BABE

    static let lcSegment: UInt32 = 0x1
    static let lcSegment64: UInt32 = 0x19
    static let lcLoadDylib: UInt32 = 0xC
    static let lcLoadWeakDylib: UInt32 = 0x8000_0018
    static let lcReexportDylib: UInt32 = 0x8000_001F
    static let lcLoadUpwardDylib: UInt32 = 0x8000_0023
    static let lcRpath: UInt32 = 0x8000_001C
    static let lcEncryptionInfo: UInt32 = 0x21
    static let lcEncryptionInfo64: UInt32 = 0x2C

    static let dylibCommands: Set<UInt32> = [lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib]

    /// Chemin « standard » de CydiaSubstrate (ElleKit) tel que LiveContainer / ESign / Feather l'attendent.
    static let substrateRpath = "@rpath/CydiaSubstrate.framework/CydiaSubstrate"
    /// Place à laisser libre dans l'en-tête pour que LiveContainer puisse encore injecter son TweakLoader.
    static let liveContainerReserve = 96

    static func isMachO(_ data: Data) -> Bool {
        guard data.count >= 32 else { return false }
        let m = data.u32(0)
        return m == magic64 || m == magic32 || data.u32BE(0) == fatMagic
    }

    static func slices(in data: Data) throws -> [MachOSlice] {
        guard data.count >= 32 else { throw JacIPAError.message("Binaire trop petit pour être un Mach-O.") }
        let magic = data.u32(0)
        if magic == magic64 || magic == magic32 {
            return [try parseSlice(data, offset: 0, size: data.count)]
        }
        if data.u32BE(0) == fatMagic {
            let n = Int(data.u32BE(4))
            guard n > 0, n < 32 else { throw JacIPAError.message("En-tête fat Mach-O invalide.") }
            var result: [MachOSlice] = []
            for i in 0..<n {
                let h = 8 + i * 20
                guard h + 20 <= data.count else { break }
                let off = Int(data.u32BE(h + 8))
                let size = Int(data.u32BE(h + 12))
                guard off >= 0, off + 32 <= data.count else { continue }
                result.append(try parseSlice(data, offset: off, size: size))
            }
            guard !result.isEmpty else { throw JacIPAError.message("Aucune architecture lisible dans ce binaire fat.") }
            return result
        }
        throw JacIPAError.message("Ce fichier n'est pas un binaire Mach-O.")
    }

    private static func parseSlice(_ d: Data, offset: Int, size: Int) throws -> MachOSlice {
        let magic = d.u32(offset)
        let is64: Bool
        switch magic {
        case magic64: is64 = true
        case magic32: is64 = false
        default: throw JacIPAError.message("Tranche Mach-O invalide à l'offset \(offset).")
        }
        let cpu = d.u32(offset + 4)
        let ncmds = Int(d.u32(offset + 16))
        let sizeofcmds = Int(d.u32(offset + 20))
        var p = offset + (is64 ? 32 : 28)
        let end = p + sizeofcmds
        guard end <= d.count else { throw JacIPAError.message("Commandes de chargement tronquées.") }

        var cryptid: UInt32?
        var dylibs: [MachODylibRef] = []
        var index = 0

        for _ in 0..<ncmds {
            guard p + 8 <= end else { break }
            let cmd = d.u32(p)
            let cmdsize = Int(d.u32(p + 4))
            guard cmdsize >= 8, p + cmdsize <= end else { break }

            if cmd == lcEncryptionInfo || cmd == lcEncryptionInfo64 {
                if cmdsize >= 20 { cryptid = d.u32(p + 16) }
            } else if dylibCommands.contains(cmd) {
                let nameOff = Int(d.u32(p + 8))
                if nameOff < cmdsize {
                    let path = d.cString(p + nameOff, maxLength: cmdsize - nameOff)
                    dylibs.append(MachODylibRef(path: path, weak: cmd == lcLoadWeakDylib, index: index))
                }
                index += 1
            }
            p += cmdsize
        }

        return MachOSlice(offset: offset, size: size, is64: is64, cpuType: cpu, ncmds: ncmds,
                          sizeofcmds: sizeofcmds, cryptid: cryptid, dylibs: dylibs)
    }

    /// Parcourt les commandes de chargement d'une tranche : (cmd, position absolue, cmdsize).
    private static func forEachCommand(in d: Data, slice: MachOSlice, _ body: (UInt32, Int, Int) -> Void) {
        var p = slice.commandsStart
        let end = slice.commandsEnd
        for _ in 0..<slice.ncmds {
            guard p + 8 <= end else { break }
            let cmd = d.u32(p)
            let cmdsize = Int(d.u32(p + 4))
            guard cmdsize >= 8, p + cmdsize <= end else { break }
            body(cmd, p, cmdsize)
            p += cmdsize
        }
    }

    // MARK: - Nettoyage

    /// Retire les commandes LC_LOAD_*DYLIB dont le chemin satisfait `matching`, dans toutes les tranches.
    /// Les commandes restantes sont tassées, la fin est mise à zéro, ncmds / sizeofcmds mis à jour.
    static func removingDylibs(from input: Data, matching: (String) -> Bool) throws -> (data: Data, removed: [String]) {
        var d = Data(input)
        var removed: [String] = []

        for slice in try slices(in: d) {
            let headerSize = slice.is64 ? 32 : 28
            let start = slice.offset + headerSize
            let end = start + slice.sizeofcmds
            var kept = Data()
            var keptCount = 0
            var p = start

            for _ in 0..<slice.ncmds {
                guard p + 8 <= end else { break }
                let cmd = d.u32(p)
                let cmdsize = Int(d.u32(p + 4))
                guard cmdsize >= 8, p + cmdsize <= end else { break }

                var drop = false
                if dylibCommands.contains(cmd) {
                    let nameOff = Int(d.u32(p + 8))
                    if nameOff < cmdsize {
                        let path = d.cString(p + nameOff, maxLength: cmdsize - nameOff)
                        if matching(path) {
                            drop = true
                            removed.append(path)
                        }
                    }
                }
                if !drop {
                    kept.append(d.copy(p, cmdsize))
                    keptCount += 1
                }
                p += cmdsize
            }

            if keptCount == slice.ncmds { continue }

            let keptEnd = start + kept.count
            d.replaceSubrange(start..<keptEnd, with: kept)
            d.replaceSubrange(keptEnd..<end, with: Data(count: end - keptEnd))
            d.putU32(UInt32(keptCount), at: slice.offset + 16)
            d.putU32(UInt32(kept.count), at: slice.offset + 20)
        }

        return (d, removed)
    }

    // MARK: - Injection

    /// Octets libres entre la fin des commandes de chargement et la première section (padding d'en-tête).
    /// nil si aucune section avec un offset fichier n'a été trouvée.
    static func headerPadding(in d: Data, slice: MachOSlice) -> Int? {
        var firstSection: Int?
        forEachCommand(in: d, slice: slice) { cmd, p, cmdsize in
            guard cmd == lcSegment64 || cmd == lcSegment else { return }
            let is64 = cmd == lcSegment64
            let segHeader = is64 ? 72 : 56
            let sectSize = is64 ? 80 : 68
            guard cmdsize >= segHeader else { return }
            let nsects = Int(d.u32(p + (is64 ? 64 : 48)))
            var s = p + segHeader
            for _ in 0..<nsects {
                guard s + sectSize <= p + cmdsize else { break }
                let off = Int(d.u32(s + (is64 ? 48 : 40)))
                let size = is64 ? Int(d.u64(s + 40)) : Int(d.u32(s + 36))
                if off > 0, size > 0 {
                    firstSection = min(firstSection ?? off, off)
                }
                s += sectSize
            }
        }
        guard let firstSection else { return nil }
        return slice.offset + firstSection - slice.commandsEnd
    }

    /// Chemins LC_RPATH d'une tranche.
    static func rpaths(in d: Data, slice: MachOSlice) -> [String] {
        var out: [String] = []
        forEachCommand(in: d, slice: slice) { cmd, p, cmdsize in
            guard cmd == lcRpath, cmdsize > 12 else { return }
            let off = Int(d.u32(p + 8))
            if off < cmdsize { out.append(d.cString(p + off, maxLength: cmdsize - off)) }
        }
        return out
    }

    /// Construit une commande « chaîne » (LC_LOAD_DYLIB, LC_RPATH) alignée sur 8 octets.
    private static func stringCommand(_ cmd: UInt32, nameOffset: Int, path: String, dylibFields: Bool) -> Data {
        let bytes = Array(path.utf8) + [0]
        let size = (nameOffset + bytes.count + 7) & ~7
        var c = Data()
        c.appendU32(cmd)
        c.appendU32(UInt32(size))
        c.appendU32(UInt32(nameOffset))
        if dylibFields {
            c.appendU32(2)              // timestamp
            c.appendU32(0x0001_0000)    // current version 1.0.0
            c.appendU32(0x0001_0000)    // compatibility version 1.0.0
        }
        c.append(contentsOf: bytes)
        c.append(Data(count: size - c.count))
        return c
    }

    /// Ajoute des LC_LOAD_DYLIB (`paths`, ex. `@rpath/GTok.dylib`) à la fin des commandes de chargement
    /// de chaque tranche, plus un LC_RPATH `rpath` s'il manque. Même principe qu'insert_dylib / optool.
    static func addingDylibs(to input: Data, paths: [String],
                             rpath: String = "@executable_path/Frameworks") throws -> (data: Data, added: [String], warnings: [String]) {
        var d = Data(input)
        var added: [String] = []
        var warnings: [String] = []

        for slice in try slices(in: d) {
            var newCmds = Data()
            var names: [String] = []
            let existing = Set(slice.dylibs.map(\.path))

            if !rpaths(in: d, slice: slice).contains(rpath) {
                newCmds.append(stringCommand(lcRpath, nameOffset: 12, path: rpath, dylibFields: false))
                names.append("LC_RPATH " + rpath)
            }
            for path in paths where !existing.contains(path) {
                newCmds.append(stringCommand(lcLoadDylib, nameOffset: 24, path: path, dylibFields: true))
                names.append("LC_LOAD_DYLIB " + path)
            }
            if names.isEmpty {
                warnings.append("Tranche \(slice.arch) : le dylib était déjà chargé, rien à ajouter.")
                continue
            }

            guard let free = headerPadding(in: d, slice: slice) else {
                throw JacIPAError.message("Tranche \(slice.arch) : impossible de mesurer l'espace libre dans l'en-tête Mach-O.")
            }
            let needed = newCmds.count + liveContainerReserve
            guard free >= needed else {
                throw JacIPAError.message("Tranche \(slice.arch) : pas assez de place dans l'en-tête Mach-O (\(free) octets libres, \(needed) nécessaires en comptant la réserve pour LiveContainer).")
            }
            let end = slice.commandsEnd
            if d.copy(end, newCmds.count).contains(where: { $0 != 0 }) {
                throw JacIPAError.message("Tranche \(slice.arch) : l'espace après les commandes de chargement n'est pas vide, injection refusée par sécurité.")
            }

            d.replaceSubrange(end..<(end + newCmds.count), with: newCmds)
            d.putU32(UInt32(slice.ncmds + names.count), at: slice.offset + 16)
            d.putU32(UInt32(slice.sizeofcmds + newCmds.count), at: slice.offset + 20)
            if added.isEmpty || slice.cpuType == 0x0100_000C { added = names }
        }

        return (d, added, warnings)
    }

    /// Dans un dylib de tweak, remplace les dépendances substrate / substitute / ellekit par
    /// `@rpath/CydiaSubstrate.framework/CydiaSubstrate` quand le nouveau chemin tient dans la commande existante.
    static func rewritingHookingDependencies(in input: Data) throws -> (data: Data, rewritten: [String], failed: [String]) {
        var d = Data(input)
        var rewritten: [String] = []
        var failed: [String] = []
        let target = Array(substrateRpath.utf8)

        for slice in try slices(in: d) {
            var edits: [(start: Int, length: Int, path: String)] = []
            forEachCommand(in: d, slice: slice) { cmd, p, cmdsize in
                guard dylibCommands.contains(cmd) else { return }
                let nameOff = Int(d.u32(p + 8))
                guard nameOff < cmdsize else { return }
                let path = d.cString(p + nameOff, maxLength: cmdsize - nameOff)
                guard path != substrateRpath, isHookingLibrary(path) else { return }
                edits.append((p + nameOff, cmdsize - nameOff, path))
            }
            for e in edits {
                if target.count + 1 <= e.length {
                    var field = Data(target)
                    field.append(Data(count: e.length - target.count))
                    d.replaceSubrange(e.start..<(e.start + e.length), with: field)
                    if !rewritten.contains(e.path) { rewritten.append(e.path) }
                } else if !failed.contains(e.path) {
                    failed.append(e.path)
                }
            }
        }
        return (d, rewritten, failed)
    }

    /// Librairie de hooking compatible avec l'API Substrate (MSHookFunction…).
    static func isHookingLibrary(_ path: String) -> Bool {
        let lower = path.lowercased()
        return lower.contains("substrate") || lower.contains("substitute") || lower.contains("ellekit")
    }

    /// Chemin fourni par iOS lui-même (pas besoin de l'embarquer dans l'IPA).
    static func isSystemLibrary(_ path: String) -> Bool {
        (path.hasPrefix("/usr/lib/") || path.hasPrefix("/System/")) && !isHookingLibrary(path)
    }
}
