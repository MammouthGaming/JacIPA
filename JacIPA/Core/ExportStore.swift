import Foundation

struct ExportEntry: Identifiable, Hashable {
    let url: URL
    let name: String
    let isDirectory: Bool
    let size: Int64
    let date: Date

    var id: String { url.path }
}

/// Une opération réussie (Deb → dylib, Extraire, Nettoyer, Injecter), pour l'onglet Historique.
struct HistoryEntry: Identifiable, Codable, Hashable {
    var id = UUID()
    var date = Date()
    let tool: String
    let source: String
    let output: String
    let details: [String]
}

/// Tout ce que JacIPA produit va dans Documents/Exports, visible dans l'app Fichiers
/// (Sur mon iPhone → JacIPA → Exports).
enum ExportStore {
    static var root: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = docs.appendingPathComponent("Exports", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static func sanitize(_ name: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._ "))
        let cleaned = name.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" }
        let text = String(cleaned).trimmingCharacters(in: CharacterSet(charactersIn: "-. "))
        return text.isEmpty ? "export" : text
    }

    /// Dossier neuf et unique : nom, nom-2, nom-3…
    static func makeFolder(named name: String) throws -> URL {
        let base = sanitize(name)
        var candidate = root.appendingPathComponent(base, isDirectory: true)
        var n = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            candidate = root.appendingPathComponent("\(base)-\(n)", isDirectory: true)
            n += 1
        }
        try FileManager.default.createDirectory(at: candidate, withIntermediateDirectories: true)
        return candidate
    }

    /// Chemin de fichier unique dans Exports.
    static func uniqueFile(named name: String) -> URL {
        let ext = (name as NSString).pathExtension
        let stem = sanitize((name as NSString).deletingPathExtension)
        var candidate = root.appendingPathComponent(ext.isEmpty ? stem : "\(stem).\(ext)")
        var n = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            candidate = root.appendingPathComponent(ext.isEmpty ? "\(stem)-\(n)" : "\(stem)-\(n).\(ext)")
            n += 1
        }
        return candidate
    }

    static func write(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    /// Copie un fichier choisi (fileImporter, « Ouvrir dans ») dans tmp pour y accéder librement.
    static func importToTemp(_ url: URL) throws -> URL {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("Imports", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let dest = dir.appendingPathComponent(url.lastPathComponent)
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.copyItem(at: url, to: dest)
        return dest
    }

    static func list(_ folder: URL = root) -> [ExportEntry] {
        let fm = FileManager.default
        let keys: [URLResourceKey] = [.isDirectoryKey, .fileSizeKey, .contentModificationDateKey]
        guard let urls = try? fm.contentsOfDirectory(at: folder, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]) else {
            return []
        }
        return urls.map { url in
            let values = try? url.resourceValues(forKeys: Set(keys))
            let isDir = values?.isDirectory ?? false
            let size: Int64 = isDir ? folderSize(url) : Int64(values?.fileSize ?? 0)
            return ExportEntry(url: url, name: url.lastPathComponent, isDirectory: isDir, size: size,
                               date: values?.contentModificationDate ?? .distantPast)
        }
        .sorted { $0.date > $1.date }
    }

    /// Tous les .dylib et .framework présents dans Exports (récursif), les plus récents d'abord.
    /// Sert au sélecteur « Injecter un dylib ».
    static func allInjectables() -> [ExportEntry] {
        let fm = FileManager.default
        let keys: [URLResourceKey] = [.isDirectoryKey, .fileSizeKey, .contentModificationDateKey]
        guard let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]) else {
            return []
        }
        var out: [ExportEntry] = []
        for case let url as URL in enumerator {
            let name = url.lastPathComponent
            let values = try? url.resourceValues(forKeys: Set(keys))
            let isDir = values?.isDirectory ?? false
            if isDir, name.hasSuffix(".framework") {
                out.append(ExportEntry(url: url, name: name, isDirectory: true, size: folderSize(url),
                                       date: values?.contentModificationDate ?? .distantPast))
                enumerator.skipDescendants()
            } else if !isDir, name.hasSuffix(".dylib") {
                out.append(ExportEntry(url: url, name: name, isDirectory: false, size: Int64(values?.fileSize ?? 0),
                                       date: values?.contentModificationDate ?? .distantPast))
            }
        }
        return out.sorted { $0.date > $1.date }
    }

    static func folderSize(_ url: URL) -> Int64 {
        guard let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.fileSizeKey]) else { return 0 }
        var total: Int64 = 0
        for case let f as URL in e {
            total += Int64((try? f.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        }
        return total
    }

    static func delete(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    /// Vide Exports (les fichiers seulement, l'historique reste).
    static func deleteAll() {
        for entry in list() { delete(entry.url) }
    }

    /// URL qui ouvre le dossier Exports dans l'app Fichiers.
    static var filesAppURL: URL? {
        URL(string: "shareddocuments://" + root.path)
    }

    // MARK: - Historique

    private static let historyLock = NSLock()
    private static let historyLimit = 200

    private static var historyURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("historique.json")
    }

    static func history() -> [HistoryEntry] {
        historyLock.lock()
        defer { historyLock.unlock() }
        return loadHistory()
    }

    private static func loadHistory() -> [HistoryEntry] {
        guard let data = try? Data(contentsOf: historyURL),
              let entries = try? JSONDecoder().decode([HistoryEntry].self, from: data) else { return [] }
        return entries
    }

    private static func saveHistory(_ entries: [HistoryEntry]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(entries) {
            try? data.write(to: historyURL, options: .atomic)
        }
    }

    /// Note une opération réussie. Appelé depuis les tâches de fond : protégé par un verrou.
    static func log(tool: String, source: String, output: String, details: [String]) {
        historyLock.lock()
        defer { historyLock.unlock() }
        var entries = loadHistory()
        entries.insert(HistoryEntry(tool: tool, source: source, output: output, details: details), at: 0)
        if entries.count > historyLimit { entries.removeLast(entries.count - historyLimit) }
        saveHistory(entries)
    }

    static func removeHistory(ids: Set<UUID>) {
        historyLock.lock()
        defer { historyLock.unlock() }
        saveHistory(loadHistory().filter { !ids.contains($0.id) })
    }

    static func clearHistory() {
        historyLock.lock()
        defer { historyLock.unlock() }
        try? FileManager.default.removeItem(at: historyURL)
    }
}
