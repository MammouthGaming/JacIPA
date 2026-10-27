import Foundation

struct ExtractedFile: Identifiable, Sendable, Hashable {
    let originalPath: String
    let exportedURL: URL
    let size: Int
    let dependencies: [String]
    let warnings: [String]

    var id: String { exportedURL.path }
}

struct DebResult: Sendable {
    let packageName: String
    let version: String?
    let exportFolder: URL
    let dylibs: [ExtractedFile]
    let plists: [ExtractedFile]
    let bundles: [String]
    let otherFiles: [String]
    let notes: [String]
}

/// Outil 1 : .deb → .dylib (+ .bundle, + filtre .plist) prêts pour LiveContainer.
enum DebExtractor {
    static func extract(url: URL) async throws -> DebResult {
        try await Task.detached(priority: .userInitiated) {
            try extractSync(url)
        }.value
    }

    static func extractSync(_ url: URL) throws -> DebResult {
        let raw = try Data(contentsOf: url)
        let members = try ArArchive.parse(raw)

        guard let dataMember = members.first(where: { $0.name.hasPrefix("data.tar") }) else {
            throw JacIPAError.message("Pas de data.tar dans ce .deb.")
        }

        // Nom et version depuis control
        var packageName = url.deletingPathExtension().lastPathComponent
        var version: String?
        var sawName = false
        if let control = members.first(where: { $0.name.hasPrefix("control.tar") }),
           let tar = try? Decompressor.decompress(control.data, filename: control.name),
           let entries = try? TarArchive.parse(tar),
           let ctl = entries.first(where: { $0.isFile && normalize($0.path) == "control" }) {
            let text = String(decoding: ctl.data, as: UTF8.self)
            for line in text.split(separator: "\n") {
                if line.hasPrefix("Name:") {
                    packageName = value(of: line)
                    sawName = true
                } else if line.hasPrefix("Package:"), !sawName {
                    packageName = value(of: line)
                } else if line.hasPrefix("Version:") {
                    version = value(of: line)
                }
            }
        }

        let tarData = try Decompressor.decompress(dataMember.data, filename: dataMember.name)
        let entries = try TarArchive.parse(tarData)
        let folder = try ExportStore.makeFolder(named: packageName)

        var dylibs: [ExtractedFile] = []
        var plists: [ExtractedFile] = []
        var bundles = Set<String>()
        var others: [String] = []
        var notes: [String] = []
        var allPaths: [String] = []
        var isRootless = false
        var isRoothide = false

        for e in entries {
            let path = normalize(e.path)
            if path.isEmpty { continue }
            allPaths.append(path + (e.isDirectory ? "/" : ""))
            if path.hasPrefix("var/jb/") { isRootless = true }
            if e.isSymlink || e.isDirectory { continue }
            guard e.isFile else { continue }

            let fileName = (path as NSString).lastPathComponent

            if path.hasSuffix(".dylib") {
                let out = folder.appendingPathComponent(fileName)
                try ExportStore.write(e.data, to: out)
                var deps: [String] = []
                var warnings: [String] = []
                if let slices = try? MachO.slices(in: e.data), let first = slices.first {
                    deps = first.dylibs.map(\.path)
                    if !slices.contains(where: { $0.cpuType == 0x0100_000C }) {
                        warnings.append("Pas de tranche arm64 : ne se chargera pas sur un iPhone récent.")
                    }
                } else {
                    warnings.append("Pas un Mach-O lisible.")
                }
                if e.data.range(of: Data("/var/jb".utf8)) != nil {
                    warnings.append("Contient des chemins /var/jb : certaines ressources peuvent manquer dans LiveContainer.")
                }
                if e.data.range(of: Data("roothide".utf8)) != nil || e.data.range(of: Data("/rootfs/".utf8)) != nil {
                    isRoothide = true
                }
                dylibs.append(ExtractedFile(originalPath: path, exportedURL: out, size: e.data.count,
                                            dependencies: deps, warnings: warnings))
            } else if path.hasSuffix(".plist"), path.contains("DynamicLibraries/") {
                let out = folder.appendingPathComponent(fileName)
                try ExportStore.write(e.data, to: out)
                plists.append(ExtractedFile(originalPath: path, exportedURL: out, size: e.data.count,
                                            dependencies: [], warnings: []))
            } else if let r = path.range(of: ".bundle/") {
                let head = String(path[..<r.upperBound].dropLast())          // .../X.bundle
                let bundleName = (head as NSString).lastPathComponent        // X.bundle
                let rest = String(path[r.upperBound...])
                let out = folder.appendingPathComponent(bundleName, isDirectory: true).appendingPathComponent(rest)
                try ExportStore.write(e.data, to: out)
                bundles.insert(bundleName)
            } else {
                others.append(path)
            }
        }

        let listing = allPaths.sorted().joined(separator: "\n")
        try ExportStore.write(Data(listing.utf8), to: folder.appendingPathComponent("CONTENU.txt"))

        if dylibs.isEmpty {
            notes.append("Aucun .dylib trouvé. Ce paquet n'est peut-être pas un tweak (thème, dépendance, préférences…).")
        }
        if isRootless { notes.append("Paquet rootless (var/jb). C'est le bon format pour extraire un .dylib.") }
        if isRoothide { notes.append("Version roothide détectée : préfère la version rootless si elle existe.") }
        if !bundles.isEmpty {
            notes.append("Les .bundle contiennent les ressources du tweak. LiveContainer ne les charge pas toujours : à tester.")
        }
        if !others.isEmpty {
            notes.append("\(others.count) autre(s) fichier(s) non exporté(s) : liste complète dans CONTENU.txt.")
        }

        return DebResult(packageName: packageName, version: version, exportFolder: folder,
                         dylibs: dylibs, plists: plists, bundles: bundles.sorted(),
                         otherFiles: others, notes: notes)
    }

    private static func normalize(_ path: String) -> String {
        var p = path
        while p.hasPrefix("./") { p.removeFirst(2) }
        while p.hasPrefix("/") { p.removeFirst() }
        return p
    }

    private static func value(of line: Substring) -> String {
        guard let colon = line.firstIndex(of: ":") else { return String(line) }
        return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
    }
}
