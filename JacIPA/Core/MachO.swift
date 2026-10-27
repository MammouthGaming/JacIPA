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
}

/// Lecture (et petit patch) des en-têtes Mach-O : fat ou thin, 32 ou 64 bits.
enum MachO {
    static let magic64: UInt32 = 0xFEED_FACF
    static let magic32: UInt32 = 0xFEED_FACE
    static let fatMagic: UInt32 = 0xCAFE_BABE

    static let lcLoadDylib: UInt32 = 0xC
    static let lcLoadWeakDylib: UInt32 = 0x8000_0018
    static let lcReexportDylib: UInt32 = 0x8000_001F
    static let lcLoadUpwardDylib: UInt32 = 0x8000_0023
    static let lcEncryptionInfo: UInt32 = 0x21
    static let lcEncryptionInfo64: UInt32 = 0x2C

    static let dylibCommands: Set<UInt32> = [lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib]

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
}
