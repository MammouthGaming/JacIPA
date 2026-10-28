import Foundation

enum FrameworkKind: String, Sendable {
    case tweak = "Tweak"
    case dependency = "Dépendance"
    case normal = "Normal"
}

struct IPAItem: Identifiable, Sendable, Hashable {
    /// Chemin dans le ZIP : `Payload/X.app/Frameworks/GTok.dylib` ou `Payload/X.app/Frameworks/Foo.framework/`
    let id: String
    let name: String
    let kind: FrameworkKind
    let reason: String
    let size: UInt64
    let loadIndex: Int?

    var isFramework: Bool { name.hasSuffix(".framework") }
}

struct IPAAnalysis: Sendable {
    let sourceURL: URL
    let appName: String
    let bundleId: String
    let version: String
    let executable: String
    let appDir: String
    let slices: [MachOSlice]
    let items: [IPAItem]
    let warnings: [String]
    let entryCount: Int

    /// true = chiffré FairPlay (inutilisable dans LiveContainer), false = déchiffré, nil = pas d'info
    var encrypted: Bool? {
        let values = slices.compactMap(\.encrypted)
        if values.isEmpty { return nil }
        return values.contains(true)
    }

    var suspicious: [IPAItem] { items.filter { $0.kind != .normal } }
    var archs: String { slices.map(\.arch).joined(separator: ", ") }
}

struct IPAActionResult: Sendable {
    let outputURL: URL
    let details: [String]
    let warnings: [String]
}

/// Outils 2, 3 et 4 : inspection d'un IPA, extraction des tweaks, nettoyage, injection.
enum IPAInspector {
    private static let knownDependencies = [
        "cydiasubstrate", "libsubstrate", "libsubstitute", "substitute", "ellekit", "libellekit",
        "cephei", "orion", "libhooker", "libblackjack", "alderis", "libcolorpicker", "libflex",
        "flex.framework", "libmryipc", "libpackageinfo", "rocketbootstrap", "libsparkapplist",
        "libactivator", "libcsutil", "libimagepicker", "preferenceloader", "libprefs"
    ]

    private static let arm64: UInt32 = 0x0100_000C

    // MARK: - Analyse

    static func analyze(url: URL) async throws -> IPAAnalysis {
        try await Task.detached(priority: .userInitiated) {
            try analyzeSync(url)
        }.value
    }

    static func analyzeSync(_ url: URL) throws -> IPAAnalysis {
        let zip = try ZipReader(url: url)

        guard let infoEntry = zip.entries.first(where: { isAppInfoPlist($0.name) }) else {
            throw JacIPAError.message("Pas de Payload/*.app/Info.plist : ce fichier n'est pas un IPA.")
        }
        let appDir = String(infoEntry.name.dropLast("Info.plist".count))
        let plistData = try zip.read(infoEntry)
        guard let plist = try PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] else {
            throw JacIPAError.message("Info.plist illisible.")
        }

        let executable = plist["CFBundleExecutable"] as? String
            ?? String(appDir.dropLast(5).split(separator: "/").last ?? "")
        let appName = plist["CFBundleDisplayName"] as? String ?? plist["CFBundleName"] as? String ?? executable
        let bundleId = plist["CFBundleIdentifier"] as? String ?? "?"
        let version = [plist["CFBundleShortVersionString"] as? String, plist["CFBundleVersion"] as? String]
            .compactMap { $0 }.joined(separator: " · ")

        var warnings: [String] = []
        var slices: [MachOSlice] = []
        if let binEntry = zip.entry(named: appDir + executable) {
            let bin = try zip.read(binEntry)
            do {
                slices = try MachO.slices(in: bin)
            } catch {
                warnings.append("Binaire principal illisible : \(error.localizedDescription)")
            }
        } else {
            warnings.append("Binaire principal introuvable (\(executable)).")
        }

        let mainSlice = slices.first(where: { $0.cpuType == arm64 }) ?? slices.first
        let loaded = mainSlice?.dylibs ?? []

        // Inventaire de Frameworks/ et des .dylib à la racine de l'app
        let fwPrefix = appDir + "Frameworks/"
        var sizes: [String: UInt64] = [:]
        var names: [String: String] = [:]
        var order: [String] = []

        func register(id: String, name: String, size: UInt64) {
            if sizes[id] == nil {
                order.append(id)
                names[id] = name
                sizes[id] = 0
            }
            sizes[id, default: 0] += size
        }

        for e in zip.entries {
            if e.name.hasPrefix(fwPrefix) {
                let rest = e.name.dropFirst(fwPrefix.count)
                guard let first = rest.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true).first else { continue }
                let top = String(first)
                if top.hasSuffix(".framework") {
                    register(id: fwPrefix + top + "/", name: top, size: e.uncompressedSize)
                } else if top.hasSuffix(".dylib") {
                    register(id: fwPrefix + top, name: top, size: e.uncompressedSize)
                }
            } else if e.name.hasPrefix(appDir), e.name.hasSuffix(".dylib") {
                let rest = e.name.dropFirst(appDir.count)
                if !rest.contains("/") {
                    register(id: e.name, name: String(rest), size: e.uncompressedSize)
                }
            }
        }

        var items: [IPAItem] = []
        for id in order {
            let name = names[id] ?? id
            let (kind, reason, index) = classify(name: name, loaded: loaded)
            items.append(IPAItem(id: id, name: name, kind: kind, reason: reason, size: sizes[id] ?? 0, loadIndex: index))
        }
        items.sort { a, b in
            if a.kind != b.kind { return rank(a.kind) < rank(b.kind) }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }

        // Dylibs chargés par l'app mais absents du paquet
        for ref in loaded where ref.path.hasPrefix("@") {
            let file = ref.fileName
            let present = items.contains { $0.name == file || ref.path.contains("/" + $0.name + "/") }
            if !present, file.hasSuffix(".dylib") {
                warnings.append("L'app charge \(file) mais il n'est pas dans l'IPA : plantage probable au lancement.")
            }
        }

        if slices.isEmpty {
            warnings.append("Impossible de dire si l'IPA est chiffré.")
        }

        return IPAAnalysis(sourceURL: url, appName: appName, bundleId: bundleId, version: version,
                           executable: executable, appDir: appDir, slices: slices, items: items,
                           warnings: warnings, entryCount: zip.entries.count)
    }

    private static func rank(_ k: FrameworkKind) -> Int {
        switch k {
        case .tweak: return 0
        case .dependency: return 1
        case .normal: return 2
        }
    }

    private static func classify(name: String, loaded: [MachODylibRef]) -> (FrameworkKind, String, Int?) {
        let lower = name.lowercased()
        let stem = (name as NSString).deletingPathExtension
        let ref = loaded.first { r in
            r.fileName == name || r.path.contains("/" + name + "/" + stem)
        }
        let position = ref.map { "chargé en position \($0.index + 1)/\(loaded.count)" }

        if knownDependencies.contains(where: { lower.contains($0) }) {
            return (.dependency, "Librairie de hooking connue" + (position.map { " · " + $0 } ?? ""), ref?.index)
        }
        if name.hasSuffix(".dylib") {
            if lower.hasPrefix("libswift") || lower.hasPrefix("libclang_rt") || lower.hasPrefix("libxctest") {
                return (.normal, "Runtime Swift / Apple", ref?.index)
            }
            if let position {
                return (.tweak, "Dylib injecté dans l'app · " + position, ref?.index)
            }
            return (.tweak, "Dylib hors runtime Apple (pas chargé directement par le binaire)", nil)
        }
        return (.normal, ref == nil ? "Framework (chargé à la demande ou par un autre)" : "Framework de l'app", ref?.index)
    }

    private static func isAppInfoPlist(_ name: String) -> Bool {
        guard name.hasPrefix("Payload/"), name.hasSuffix("/Info.plist") else { return false }
        let parts = name.split(separator: "/")
        return parts.count == 3 && parts[1].hasSuffix(".app")
    }

    // MARK: - Extraction des tweaks

    static func extract(_ analysis: IPAAnalysis, items: [IPAItem]) async throws -> IPAActionResult {
        try await Task.detached(priority: .userInitiated) {
            try extractSync(analysis, items: items)
        }.value
    }

    static func extractSync(_ analysis: IPAAnalysis, items: [IPAItem]) throws -> IPAActionResult {
        guard !items.isEmpty else { throw JacIPAError.message("Rien de sélectionné.") }
        let zip = try ZipReader(url: analysis.sourceURL)
        let folder = try ExportStore.makeFolder(named: analysis.appName + "-tweaks")
        var details: [String] = []

        for item in items {
            if item.isFramework {
                let parent = (item.id as NSString).deletingLastPathComponent  // .../Frameworks
                for e in zip.entries(withPrefix: item.id) where !e.isDirectory && !e.isSymlink {
                    let rel = String(e.name.dropFirst(parent.count + 1))
                    try ExportStore.write(try zip.read(e), to: folder.appendingPathComponent(rel))
                }
                details.append("\(item.name)/ exporté")
            } else if let e = zip.entry(named: item.id) {
                try ExportStore.write(try zip.read(e), to: folder.appendingPathComponent(item.name))
                details.append("\(item.name) exporté")
            }
        }

        ExportStore.log(tool: "Extraire", source: analysis.sourceURL.lastPathComponent,
                        output: folder.lastPathComponent, details: details)
        return IPAActionResult(outputURL: folder, details: details,
                               warnings: ["Pour LiveContainer : importe les .dylib dans Tweaks → dossier de l'app. Les .framework marchent rarement tels quels."])
    }

    // MARK: - Nettoyage

    static func clean(_ analysis: IPAAnalysis, remove items: [IPAItem]) async throws -> IPAActionResult {
        try await Task.detached(priority: .userInitiated) {
            try cleanSync(analysis, remove: items)
        }.value
    }

    static func cleanSync(_ analysis: IPAAnalysis, remove items: [IPAItem]) throws -> IPAActionResult {
        guard !items.isEmpty else { throw JacIPAError.message("Rien de sélectionné.") }
        let zip = try ZipReader(url: analysis.sourceURL)
        let output = ExportStore.uniqueFile(named: ExportStore.sanitize(analysis.appName) + "-clean.ipa")
        let writer = try ZipWriter(url: output)

        let removePrefixes = items.map(\.id)
        let removeNames = items.map(\.name)
        let binPath = analysis.appDir + analysis.executable
        var removedCommands: [String] = []
        var skipped = 0
        var warnings: [String] = []

        for e in zip.entries {
            if removePrefixes.contains(where: { e.name.hasPrefix($0) }) {
                skipped += 1
                continue
            }
            if e.name == binPath {
                let bin = try zip.read(e)
                let result = try MachO.removingDylibs(from: bin) { path in
                    removeNames.contains { n in
                        path.hasSuffix("/" + n) || path.contains("/" + n + "/")
                    }
                }
                removedCommands = result.removed
                try writer.addStored(path: e.name, data: result.data, externalAttributes: e.externalAttributes,
                                     dosTime: e.dosTime, dosDate: e.dosDate)
            } else {
                let raw = try zip.rawCompressedData(of: e)
                try writer.addRaw(path: e.name, method: e.method, crc32: e.crc32, compressed: raw,
                                  uncompressedSize: e.uncompressedSize, externalAttributes: e.externalAttributes,
                                  dosTime: e.dosTime, dosDate: e.dosDate)
            }
        }
        try writer.finish()

        // Un dylib retiré qui n'était pas en dernière position décale les ordinaux : risque.
        let total = (analysis.slices.first(where: { $0.cpuType == arm64 }) ?? analysis.slices.first)?.dylibs.count ?? 0
        for item in items {
            if let idx = item.loadIndex, idx < total - 1 {
                warnings.append("\(item.name) n'était pas le dernier dylib chargé (\(idx + 1)/\(total)). Si l'app plante au lancement, c'est ça.")
            }
        }
        if removedCommands.isEmpty {
            warnings.append("Aucune commande de chargement retirée du binaire : les fichiers ont été enlevés mais le binaire n'y faisait pas référence.")
        }
        warnings.append("La signature de l'IPA n'est plus valide : normal, LiveContainer / SideStore re-signent à l'import.")

        var details = ["\(skipped) fichier(s) retiré(s)"]
        details += removedCommands.map { "Commande retirée : \($0)" }
        ExportStore.log(tool: "Nettoyer", source: analysis.sourceURL.lastPathComponent,
                        output: output.lastPathComponent, details: details)
        return IPAActionResult(outputURL: output, details: details, warnings: warnings)
    }

    // MARK: - Injection

    /// `files` : des .dylib (exportés par Deb → dylib ou choisis dans Fichiers) et/ou des dossiers .framework
    /// (ex. CydiaSubstrate.framework pris dans Fichiers → LiveContainer → Tweaks).
    static func inject(_ analysis: IPAAnalysis, files: [URL]) async throws -> IPAActionResult {
        try await Task.detached(priority: .userInitiated) {
            try injectSync(analysis, files: files)
        }.value
    }

    private struct InjectPayload {
        let zipPath: String
        let data: Data
        let executable: Bool
    }

    static func injectSync(_ analysis: IPAAnalysis, files: [URL]) throws -> IPAActionResult {
        guard !files.isEmpty else { throw JacIPAError.message("Rien à injecter.") }
        if analysis.encrypted == true {
            throw JacIPAError.message("IPA chiffré (FairPlay) : inutile d'injecter, l'app ne se lancerait pas dans LiveContainer.")
        }
        let zip = try ZipReader(url: analysis.sourceURL)
        let binPath = analysis.appDir + analysis.executable
        guard zip.entry(named: binPath) != nil else {
            throw JacIPAError.message("Binaire principal introuvable (\(analysis.executable)).")
        }
        let fwPrefix = analysis.appDir + "Frameworks/"
        let fm = FileManager.default

        var payloads: [InjectPayload] = []
        var dylibNames: [String] = []
        var frameworkNames: [String] = []
        var details: [String] = []
        var warnings: [String] = []
        var dependencies: [(dylib: String, path: String)] = []

        for url in files {
            var isDir: ObjCBool = false
            let name = url.lastPathComponent
            guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else {
                throw JacIPAError.message("Introuvable : \(name)")
            }

            if isDir.boolValue {
                guard name.hasSuffix(".framework") else {
                    throw JacIPAError.message("\(name) : seuls les dossiers .framework peuvent être injectés.")
                }
                let stem = (name as NSString).deletingPathExtension
                let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey]
                guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]) else {
                    throw JacIPAError.message("Impossible de lire \(name).")
                }
                let base = url.path + "/"
                var count = 0
                for case let f as URL in enumerator {
                    let values = try? f.resourceValues(forKeys: Set(keys))
                    guard values?.isRegularFile == true, values?.isSymbolicLink != true else { continue }
                    guard f.path.hasPrefix(base) else { continue }
                    let rel = String(f.path.dropFirst(base.count))
                    let data = try Data(contentsOf: f)
                    payloads.append(InjectPayload(zipPath: fwPrefix + name + "/" + rel, data: data, executable: rel == stem))
                    count += 1
                }
                guard count > 0 else { throw JacIPAError.message("\(name) est vide.") }
                frameworkNames.append(name)
                details.append("\(name) copié dans Frameworks/ (\(count) fichiers)")
            } else {
                let data = try Data(contentsOf: url)
                guard MachO.isMachO(data) else { throw JacIPAError.message("\(name) n'est pas un binaire Mach-O.") }
                let slices = try MachO.slices(in: data)
                guard let arm = slices.first(where: { $0.cpuType == arm64 }) else {
                    throw JacIPAError.message("\(name) n'a pas de tranche arm64.")
                }
                let fileName = name.hasSuffix(".dylib") ? name : name + ".dylib"
                let patched = try MachO.rewritingHookingDependencies(in: data)
                for p in patched.rewritten {
                    details.append("\(fileName) : dépendance \(p) → \(MachO.substrateRpath)")
                }
                for p in patched.failed {
                    warnings.append("\(fileName) : dépendance \(p) impossible à réécrire (pas la place dans la commande).")
                }
                for ref in arm.dylibs {
                    let path = patched.rewritten.contains(ref.path) ? MachO.substrateRpath : ref.path
                    dependencies.append((fileName, path))
                }
                payloads.append(InjectPayload(zipPath: fwPrefix + fileName, data: patched.data, executable: true))
                dylibNames.append(fileName)
            }
        }

        // Nom de sortie : Spotify+GTok.ipa
        let stems = dylibNames.map { ($0 as NSString).deletingPathExtension }
        let suffix = stems.isEmpty ? "inject" : stems.joined(separator: "+")
        let output = ExportStore.uniqueFile(named: ExportStore.sanitize(analysis.appName) + "+" + suffix + ".ipa")
        let writer = try ZipWriter(url: output)
        let replacedPaths = Set(payloads.map(\.zipPath))
        let replacedFrameworkPrefixes = frameworkNames.map { fwPrefix + $0 + "/" }
        let stamp = ZipWriter.dosDateTime()
        var addedCommands: [String] = []
        var replaced = 0

        for e in zip.entries {
            if replacedPaths.contains(e.name) || replacedFrameworkPrefixes.contains(where: { e.name.hasPrefix($0) }) {
                replaced += 1
                continue
            }
            if e.name == binPath {
                let bin = try zip.read(e)
                if dylibNames.isEmpty {
                    let raw = try zip.rawCompressedData(of: e)
                    try writer.addRaw(path: e.name, method: e.method, crc32: e.crc32, compressed: raw,
                                      uncompressedSize: e.uncompressedSize, externalAttributes: e.externalAttributes,
                                      dosTime: e.dosTime, dosDate: e.dosDate)
                } else {
                    let result = try MachO.addingDylibs(to: bin, paths: dylibNames.map { "@rpath/" + $0 })
                    addedCommands = result.added
                    warnings += result.warnings
                    try writer.addStored(path: e.name, data: result.data, externalAttributes: e.externalAttributes,
                                         dosTime: e.dosTime, dosDate: e.dosDate)
                }
            } else {
                let raw = try zip.rawCompressedData(of: e)
                try writer.addRaw(path: e.name, method: e.method, crc32: e.crc32, compressed: raw,
                                  uncompressedSize: e.uncompressedSize, externalAttributes: e.externalAttributes,
                                  dosTime: e.dosTime, dosDate: e.dosDate)
            }
        }
        for p in payloads {
            let mode: UInt32 = p.executable ? 0o100755 : 0o100644
            try writer.addStored(path: p.zipPath, data: p.data, externalAttributes: mode << 16,
                                 dosTime: stamp.time, dosDate: stamp.date)
        }
        try writer.finish()

        details.insert("\(dylibNames.count) dylib(s) et \(frameworkNames.count) framework(s) ajoutés dans \(analysis.executable).app/Frameworks/", at: 0)
        if replaced > 0 { details.append("\(replaced) fichier(s) déjà présent(s) remplacé(s)") }
        details += addedCommands.map { "Commande ajoutée : \($0)" }

        // Dépendances des dylibs injectés : tout ce qui n'est ni système ni dans l'IPA finira en plantage.
        var bundled = Set(zip.entries.map(\.name))
        for p in payloads { bundled.insert(p.zipPath) }
        func isBundled(_ dep: String) -> Bool {
            let file = (dep as NSString).lastPathComponent
            let tail = dep.split(separator: "/").suffix(2).joined(separator: "/")
            return bundled.contains { $0.hasPrefix(fwPrefix) && ($0 == fwPrefix + file || $0.hasSuffix("/" + tail)) }
        }
        var reported = Set<String>()
        for dep in dependencies {
            guard !MachO.isSystemLibrary(dep.path), !isBundled(dep.path), reported.insert(dep.path).inserted else { continue }
            if MachO.isHookingLibrary(dep.path) {
                warnings.append("\(dep.dylib) a besoin de CydiaSubstrate (\(dep.path)) et il n'est pas dans l'IPA. Si l'app plante au lancement : refais l'injection en ajoutant CydiaSubstrate.framework (Fichiers → LiveContainer → Tweaks).")
            } else {
                warnings.append("\(dep.dylib) dépend de \(dep.path), absent de l'IPA : plantage possible au lancement.")
            }
        }
        warnings.append("La signature de l'IPA n'est plus valide : normal, LiveContainer / SideStore re-signent à l'import.")

        ExportStore.log(tool: "Injecter", source: analysis.sourceURL.lastPathComponent,
                        output: output.lastPathComponent, details: details)
        return IPAActionResult(outputURL: output, details: details, warnings: warnings)
    }

    // MARK: - Mettre à jour (transplantation)

    /// Mise à jour d'une app installée dans LiveContainer avec un nouvel IPA de la même app.
    ///
    /// Tout ce que l'app installée a EN PLUS du stock est transplanté tel quel dans le nouvel IPA :
    /// - les .dylib et .framework de Frameworks/ absents du nouvel IPA ;
    /// - les .bundle / .framework / .dylib à la racine de l'app absents du nouvel IPA (ex. MoeMulti.bundle,
    ///   BHTwitter.bundle : c'est là que les IPA « Moe » rangent les vrais tweaks et le correctif de connexion) ;
    /// - les commandes de chargement ajoutées au binaire principal (LC_LOAD_DYLIB **ou** LC_LOAD_WEAK_DYLIB),
    ///   recréées à l'identique et dans le même ordre.
    ///
    /// Pourquoi pas simplement `inject` avec Frameworks/*.dylib ? Parce que ça perdait les .bundle, les frameworks
    /// non-hooking (Alderis), transformait des LOAD_WEAK_DYLIB en LOAD_DYLIB et inventait une commande pour des
    /// dylibs que rien ne charge (libsubstrate.dylib) : l'app mise à jour démarrait sans tweaks ni correctifs.
    static func update(_ analysis: IPAAnalysis, from oldApp: URL, executable: String) async throws -> IPAActionResult {
        try await Task.detached(priority: .userInitiated) {
            try updateSync(analysis, from: oldApp, executable: executable)
        }.value
    }

    /// Noms à la racine de l'app installée qui ne sont jamais des ajouts (LiveContainer, signature, métadonnées).
    private static let neverTransplanted: Set<String> = [
        "Info.plist", "LCAppInfo.plist", "PkgInfo", "_CodeSignature", "SC_Info", "embedded.mobileprovision",
        "CodeResources", "Frameworks", "PlugIns", "Watch", "Extensions", "SystemExtensions",
    ]

    static func updateSync(_ analysis: IPAAnalysis, from oldApp: URL, executable: String) throws -> IPAActionResult {
        if analysis.encrypted == true {
            throw JacIPAError.message("Cet IPA est chiffré (FairPlay) : il ne se lancera pas dans LiveContainer. Prends la version déchiffrée.")
        }
        let zip = try ZipReader(url: analysis.sourceURL)
        let binPath = analysis.appDir + analysis.executable
        guard let binEntry = zip.entry(named: binPath) else {
            throw JacIPAError.message("Binaire principal introuvable dans le nouvel IPA (\(analysis.executable)).")
        }
        let fm = FileManager.default
        let oldExec = oldApp.appendingPathComponent(executable)
        guard let oldData = try? Data(contentsOf: oldExec), MachO.isMachO(oldData) else {
            throw JacIPAError.message("Impossible de lire le binaire de l'app installée (\(executable)).")
        }

        // 1. Commandes ajoutées dans l'ancien binaire = la fin de sa liste de dylibs qui n'existe pas dans
        //    le nouveau binaire (une injection ajoute toujours à la fin). Ce que LiveContainer ajoute lui-même
        //    (TweakLoader) est ignoré : il le remettra à l'import.
        let oldSlices = try MachO.slices(in: oldData)
        let newBin = try zip.read(binEntry)
        let newSlices = try MachO.slices(in: newBin)
        guard let oldSlice = oldSlices.first(where: { $0.cpuType == arm64 }) ?? oldSlices.first,
              let newSlice = newSlices.first(where: { $0.cpuType == arm64 }) ?? newSlices.first else {
            throw JacIPAError.message("Binaire Mach-O sans tranche lisible.")
        }
        let newPaths = Set(newSlice.dylibs.map(\.path))
        let oldRefs = oldSlice.dylibs.filter { !$0.path.contains("TweakLoader.dylib") && !$0.path.contains("/Tweaks/") }
        var injectedRefs: [MachODylibRef] = []
        for ref in oldRefs.reversed() {
            if newPaths.contains(ref.path) || MachO.isSystemLibrary(ref.path) { break }
            injectedRefs.insert(ref, at: 0)
        }

        // 2. Fichiers ajoutés : racine (.bundle / .framework / .dylib) et Frameworks/ (.dylib / .framework),
        //    tout ce qui n'existe pas dans le nouvel IPA. Copie octet pour octet.
        let appDir = analysis.appDir
        let fwPrefix = appDir + "Frameworks/"
        var payloads: [InjectPayload] = []
        var transplantedDirs: [String] = []   // chemins relatifs à l'app : "MoeMulti.bundle", "Frameworks/Alderis.framework"
        var transplantedFiles: [String] = []  // idem : "Frameworks/sideloadFixerLol.dylib"
        var details: [String] = []
        var warnings: [String] = []

        func existsInNew(_ rel: String) -> Bool {
            zip.entry(named: appDir + rel) != nil || !zip.entries(withPrefix: appDir + rel + "/").isEmpty
        }
        func addDirectory(_ dir: URL, rel: String) throws {
            let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey]
            guard let enumerator = fm.enumerator(at: dir, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]) else {
                throw JacIPAError.message("Impossible de lire \(rel).")
            }
            let base = dir.path + "/"
            var count = 0
            for case let f as URL in enumerator {
                let values = try? f.resourceValues(forKeys: Set(keys))
                guard values?.isRegularFile == true, values?.isSymbolicLink != true else { continue }
                guard f.path.hasPrefix(base) else { continue }
                let sub = String(f.path.dropFirst(base.count))
                let data = try Data(contentsOf: f)
                payloads.append(InjectPayload(zipPath: appDir + rel + "/" + sub, data: data, executable: MachO.isMachO(data)))
                count += 1
            }
            guard count > 0 else { return }
            transplantedDirs.append(rel)
            details.append("\(rel)/ transplanté (\(count) fichiers)")
        }
        func addFile(_ file: URL, rel: String) throws {
            let data = try Data(contentsOf: file)
            payloads.append(InjectPayload(zipPath: appDir + rel, data: data, executable: MachO.isMachO(data)))
            transplantedFiles.append(rel)
            details.append("\(rel) transplanté (\(Int64(data.count).fileSizeText))")
        }
        func scan(_ folder: URL, relPrefix: String, dirExtensions: Set<String>, fileExtensions: Set<String>) throws {
            let keys: [URLResourceKey] = [.isDirectoryKey, .isSymbolicLinkKey]
            guard let items = try? fm.contentsOfDirectory(at: folder, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]) else {
                return
            }
            for item in items.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                let name = item.lastPathComponent
                if neverTransplanted.contains(name) || name == executable { continue }
                let values = try? item.resourceValues(forKeys: Set(keys))
                if values?.isSymbolicLink == true { continue }
                let ext = (name as NSString).pathExtension.lowercased()
                let rel = relPrefix + name
                if values?.isDirectory == true {
                    guard dirExtensions.contains(ext), !existsInNew(rel) else { continue }
                    try addDirectory(item, rel: rel)
                } else {
                    guard fileExtensions.contains(ext), !existsInNew(rel) else { continue }
                    try addFile(item, rel: rel)
                }
            }
        }
        try scan(oldApp, relPrefix: "", dirExtensions: ["bundle", "framework"], fileExtensions: ["dylib"])
        try scan(oldApp.appendingPathComponent("Frameworks", isDirectory: true), relPrefix: "Frameworks/",
                 dirExtensions: ["framework"], fileExtensions: ["dylib"])

        // 2b. Un .bundle à la racine présent dans les deux IPA mais qui va avec un dylib transplanté
        //     (BHTwitter.bundle ↔ BHTwitter.dylib) : on garde celui de l'app installée, cohérent avec son dylib.
        let dylibStems = Set(payloads.compactMap { p -> String? in
            let file = (p.zipPath as NSString).lastPathComponent
            return file.hasSuffix(".dylib") ? (file as NSString).deletingPathExtension : nil
        })
        if !dylibStems.isEmpty,
           let items = try? fm.contentsOfDirectory(at: oldApp, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) {
            for item in items.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                let name = item.lastPathComponent
                guard name.hasSuffix(".bundle"),
                      (try? item.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true,
                      dylibStems.contains((name as NSString).deletingPathExtension),
                      existsInNew(name) else { continue }
                try addDirectory(item, rel: name)
                details.append("\(name)/ remplace celui du nouvel IPA (il va avec le dylib transplanté du même nom)")
            }
        }

        let newVersion = analysis.version.split(separator: " ").first.map(String.init) ?? analysis.version
        let baseName = ExportStore.sanitize(analysis.appName) + "-" + newVersion

        // 3. Rien d'ajouté : l'IPA est copié tel quel, il n'y a qu'à le partager.
        if payloads.isEmpty && injectedRefs.isEmpty {
            let output = ExportStore.uniqueFile(named: baseName + ".ipa")
            try fm.copyItem(at: analysis.sourceURL, to: output)
            let note = "Aucun ajout dans l'app installée (ni dylib, ni framework, ni .bundle) : IPA copié tel quel."
            ExportStore.log(tool: "Mettre à jour", source: analysis.sourceURL.lastPathComponent,
                            output: output.lastPathComponent, details: [note])
            return IPAActionResult(outputURL: output, details: [note], warnings: [])
        }

        // 4. Réécriture du zip : entrées du nouvel IPA (recopiées compressées), binaire principal patché,
        //    puis les fichiers transplantés.
        let output = ExportStore.uniqueFile(named: baseName + "+tweaks.ipa")
        let writer = try ZipWriter(url: output)
        let replacedPaths = Set(payloads.map(\.zipPath))
        let replacedPrefixes = transplantedDirs.map { appDir + $0 + "/" }
        let stamp = ZipWriter.dosDateTime()
        var addedCommands: [String] = []

        for e in zip.entries {
            if replacedPaths.contains(e.name) || replacedPrefixes.contains(where: { e.name.hasPrefix($0) }) { continue }
            if e.name == binPath, !injectedRefs.isEmpty {
                // Même ordre et même type de commande (LOAD_DYLIB ou LOAD_WEAK_DYLIB) que dans l'app installée :
                // on avance par séries consécutives de même type.
                var bin = newBin
                var i = 0
                while i < injectedRefs.count {
                    let weak = injectedRefs[i].weak
                    var run: [String] = []
                    while i < injectedRefs.count, injectedRefs[i].weak == weak {
                        run.append(injectedRefs[i].path)
                        i += 1
                    }
                    let result = try MachO.addingDylibs(to: bin, paths: run, weak: weak)
                    bin = result.data
                    addedCommands += result.added
                    warnings += result.warnings
                }
                try writer.addStored(path: e.name, data: bin, externalAttributes: e.externalAttributes,
                                     dosTime: e.dosTime, dosDate: e.dosDate)
            } else {
                let raw = try zip.rawCompressedData(of: e)
                try writer.addRaw(path: e.name, method: e.method, crc32: e.crc32, compressed: raw,
                                  uncompressedSize: e.uncompressedSize, externalAttributes: e.externalAttributes,
                                  dosTime: e.dosTime, dosDate: e.dosDate)
            }
        }
        for p in payloads {
            let mode: UInt32 = p.executable ? 0o100755 : 0o100644
            try writer.addStored(path: p.zipPath, data: p.data, externalAttributes: mode << 16,
                                 dosTime: stamp.time, dosDate: stamp.date)
        }
        try writer.finish()

        // 5. Compte rendu.
        let count = transplantedDirs.count + transplantedFiles.count
        details.insert("\(count) élément(s) de l'app installée transplanté(s) dans le nouvel IPA, \(addedCommands.count) commande(s) de chargement recréée(s).", at: 0)
        details += addedCommands.map { "Commande ajoutée : \($0)" }

        // Chaque commande recréée doit pointer sur un fichier présent (transplanté ou déjà dans le nouvel IPA).
        var bundled = Set(zip.entries.map(\.name))
        for p in payloads { bundled.insert(p.zipPath) }
        for ref in injectedRefs {
            let file = ref.fileName
            let tail = ref.path.split(separator: "/").suffix(2).joined(separator: "/")
            let present = bundled.contains { $0.hasPrefix(appDir) && ($0 == fwPrefix + file || $0.hasSuffix("/" + tail)) }
            if !present {
                warnings.append(ref.weak
                    ? "\(ref.path) : fichier introuvable (commande faible : l'app démarre quand même, sans ce tweak)."
                    : "\(ref.path) : fichier introuvable, plantage possible au lancement.")
            }
        }
        let names = (transplantedDirs + transplantedFiles).joined(separator: " ")
        if names.contains("sideloadFixerLol") || names.contains("zxPluginsInject") || names.contains("MoeMulti") {
            details.append("Correctifs sideload / connexion de Moe conservés (sideloadFixerLol, zxPluginsInject, MoeMulti.bundle avec MoeLoginFix).")
        }
        warnings.append("La signature de l'IPA n'est plus valide : normal, LiveContainer / SideStore re-signent à l'import.")

        ExportStore.log(tool: "Mettre à jour", source: analysis.sourceURL.lastPathComponent,
                        output: output.lastPathComponent, details: details)
        return IPAActionResult(outputURL: output, details: details, warnings: warnings)
    }
}
