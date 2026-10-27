import Foundation

/// Une app installée dans LiveContainer (Documents/Applications/<bundleId>.app).
struct InstalledApp: Identifiable, Hashable, Sendable {
    let id: String            // nom du dossier dans Applications/ (sans .app)
    let bundleURL: URL
    let name: String
    let bundleId: String
    let version: String       // CFBundleShortVersionString
    let build: String         // CFBundleVersion
    let executable: String
    let iconURL: URL?
    let tweaks: [String]      // .dylib injectés dans Frameworks/
    let frameworks: [String]  // .framework de hooking (CydiaSubstrate, ElleKit…) dans Frameworks/
    let size: Int64
    let isSelf: Bool          // JacIPA lui-même

    var versionText: String {
        build.isEmpty || build == version ? version : "\(version) (\(build))"
    }

    /// Fichiers à réinjecter dans un nouvel IPA de la même app.
    var injectableURLs: [URL] {
        let fw = bundleURL.appendingPathComponent("Frameworks", isDirectory: true)
        return tweaks.map { fw.appendingPathComponent($0) } + frameworks.map { fw.appendingPathComponent($0, isDirectory: true) }
    }
}

/// Lecture de la bibliothèque LiveContainer.
///
/// JacIPA tourne *dans* LiveContainer : son propre .app est dans
/// `…/LiveContainer/Documents/Applications/com.mammouthgaming.JacIPA.app`. En remontant d'un
/// dossier on retrouve toutes les apps installées. Si ça ne marche pas (dossier caché par
/// LiveContainer, autre disposition), l'utilisateur choisit « Applications » une fois via
/// Fichiers et on garde un signet.
enum InstalledApps {
    private static let bookmarkKey = "applicationsFolderBookmark"

    /// Dossier Applications déduit de l'emplacement de JacIPA, s'il a la bonne forme.
    /// LiveContainer range les apps soit en `Applications/<bundleId>.app` (récent),
    /// soit en `Applications/<id>/X.app` (ancien) : on regarde 1 puis 2 niveaux au-dessus.
    static var automaticFolder: URL? {
        let own = Bundle.main.bundleURL.resolvingSymlinksInPath()
        let candidates = [own.deletingLastPathComponent(),
                          own.deletingLastPathComponent().deletingLastPathComponent()]
        for candidate in candidates where candidate.lastPathComponent == "Applications" {
            if isApplicationsFolder(candidate) { return candidate }
        }
        return nil
    }

    /// Dossier choisi par l'utilisateur (signet), s'il existe encore.
    static var bookmarkedFolder: URL? {
        guard let data = UserDefaults.standard.data(forKey: bookmarkKey) else { return nil }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: data, bookmarkDataIsStale: &stale) else { return nil }
        if stale { UserDefaults.standard.removeObject(forKey: bookmarkKey) }
        return url
    }

    static func saveBookmark(for url: URL) throws {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let data = try url.bookmarkData(options: .minimalBookmark, includingResourceValuesForKeys: nil, relativeTo: nil)
        UserDefaults.standard.set(data, forKey: bookmarkKey)
    }

    static func forgetBookmark() {
        UserDefaults.standard.removeObject(forKey: bookmarkKey)
    }

    /// Le dossier à scanner : signet d'abord (choix explicite), sinon déduction automatique.
    static var folder: URL? { bookmarkedFolder ?? automaticFolder }

    /// Dossier choisi via Fichiers : l'accès « security-scoped » doit rester ouvert tant qu'on lit
    /// dedans (icônes, dylibs à réinjecter). On l'ouvre une fois et on le garde.
    nonisolated(unsafe) private static var accessedFolder: URL?
    private static func ensureAccess(_ url: URL) {
        if accessedFolder == url { return }
        if let old = accessedFolder { old.stopAccessingSecurityScopedResource() }
        accessedFolder = url.startAccessingSecurityScopedResource() ? url : nil
    }

    /// true si le dossier vient de la déduction automatique (JacIPA tourne bien dans LiveContainer).
    static var isAutomatic: Bool { bookmarkedFolder == nil && automaticFolder != nil }

    /// Un dossier Applications contient au moins un .app (directement ou dans un sous-dossier).
    static func isApplicationsFolder(_ url: URL) -> Bool {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return !appBundles(in: url).isEmpty
    }

    /// Tous les bundles .app du dossier : `(identifiant du dossier, URL du .app)`.
    /// Gère `X.app` directement et `<id>/X.app`.
    private static func appBundles(in folder: URL) -> [(id: String, bundle: URL)] {
        guard let children = try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else {
            return []
        }
        var found: [(id: String, bundle: URL)] = []
        for child in children where (try? child.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
            if child.pathExtension == "app" {
                found.append((child.deletingPathExtension().lastPathComponent, child))
            } else if let bundle = appBundle(in: child) {
                found.append((child.lastPathComponent, bundle))
            }
        }
        return found
    }

    private static func appBundle(in folder: URL) -> URL? {
        guard let items = try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return nil
        }
        return items.first { $0.pathExtension == "app" }
    }

    // MARK: - Scan

    static func scan() async throws -> [InstalledApp] {
        try await Task.detached(priority: .userInitiated) {
            try scanSync()
        }.value
    }

    static func scanSync() throws -> [InstalledApp] {
        guard let folder else {
            throw JacIPAError.message("Dossier Applications de LiveContainer introuvable. Choisis-le dans Fichiers (Sur mon iPhone → LiveContainer → Applications).")
        }
        ensureAccess(folder)

        let ownURL = Bundle.main.bundleURL.resolvingSymlinksInPath()
        var apps: [InstalledApp] = []

        for entry in appBundles(in: folder) {
            if let app = read(bundle: entry.bundle, id: entry.id, ownURL: ownURL) {
                apps.append(app)
            }
        }
        return apps.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// Identifiant de JacIPA (défini en dur : dans LiveContainer, `Bundle.main.bundleIdentifier`
    /// peut être celui de LiveContainer).
    static let ownBundleId = "com.mammouthgaming.JacIPA"

    private static func read(bundle: URL, id: String, ownURL: URL) -> InstalledApp? {
        let plistURL = bundle.appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return nil
        }
        let executable = plist["CFBundleExecutable"] as? String ?? bundle.deletingPathExtension().lastPathComponent
        let name = plist["CFBundleDisplayName"] as? String ?? plist["CFBundleName"] as? String ?? executable
        // LiveContainer peut remplacer CFBundleIdentifier par le sien (option « bundle id de LC »)
        // et garde l'original dans LCOrignalBundleIdentifier (faute d'orthographe voulue, c'est leur clé).
        let bundleId = plist["LCOrignalBundleIdentifier"] as? String
            ?? plist["CFBundleIdentifier"] as? String
            ?? "?"
        let version = plist["CFBundleShortVersionString"] as? String ?? ""
        let build = plist["CFBundleVersion"] as? String ?? ""

        let (tweaks, frameworks) = injectedFiles(in: bundle)

        return InstalledApp(id: id, bundleURL: bundle, name: name, bundleId: bundleId, version: version, build: build,
                            executable: executable, iconURL: iconURL(in: bundle, plist: plist),
                            tweaks: tweaks, frameworks: frameworks, size: ExportStore.folderSize(bundle),
                            isSelf: bundleId == ownBundleId || bundle.resolvingSymlinksInPath().path == ownURL.path)
    }

    /// Dylibs de tweak et frameworks de hooking présents dans Frameworks/.
    private static func injectedFiles(in bundle: URL) -> ([String], [String]) {
        let fw = bundle.appendingPathComponent("Frameworks", isDirectory: true)
        guard let items = try? FileManager.default.contentsOfDirectory(at: fw, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return ([], [])
        }
        var tweaks: [String] = []
        var frameworks: [String] = []
        for item in items {
            let name = item.lastPathComponent
            let lower = name.lowercased()
            if name.hasSuffix(".dylib") {
                if lower.hasPrefix("libswift") || lower.hasPrefix("libclang_rt") || lower.hasPrefix("libxctest") { continue }
                tweaks.append(name)
            } else if name.hasSuffix(".framework"), MachO.isHookingLibrary(name) {
                frameworks.append(name)
            }
        }
        return (tweaks.sorted(), frameworks.sorted())
    }

    /// Meilleure icône disponible dans le bundle (les apps compilées gardent des PNG
    /// `AppIcon60x60@2x.png` à la racine même avec un Assets.car).
    private static func iconURL(in bundle: URL, plist: [String: Any]) -> URL? {
        var names: [String] = []
        for key in ["CFBundleIcons", "CFBundleIcons~ipad"] {
            if let icons = plist[key] as? [String: Any],
               let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
               let files = primary["CFBundleIconFiles"] as? [String] {
                names += files.reversed()  // la plus grande est en général la dernière
            }
        }
        if let files = plist["CFBundleIconFiles"] as? [String] { names += files.reversed() }
        if let file = plist["CFBundleIconFile"] as? String { names.append(file) }
        names.append("AppIcon60x60")
        names.append("AppIcon")

        let fm = FileManager.default
        for base in names {
            for suffix in ["@3x.png", "@2x.png", ".png", ""] {
                let candidate = bundle.appendingPathComponent(base + suffix)
                if fm.fileExists(atPath: candidate.path), !candidate.hasDirectoryPath { return candidate }
            }
        }
        // Dernier recours : n'importe quel PNG dont le nom contient « icon ».
        if let items = try? fm.contentsOfDirectory(at: bundle, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) {
            return items.first { $0.pathExtension.lowercased() == "png" && $0.lastPathComponent.lowercased().contains("icon") }
        }
        return nil
    }
}
