import Foundation

/// Ce que l'App Store dit de l'app (API publique iTunes Lookup, sans clé).
struct StoreInfo: Codable, Hashable, Sendable {
    let trackId: Int
    let name: String
    let version: String
    let releaseDate: Date?
    let notes: String?
    let storeURL: URL
    let artworkURL: URL?

    var decryptDayURL: URL { URL(string: "https://decrypt.day/app/id\(trackId)")! }
}

/// Ce que decrypt.day propose pour cette app.
enum DecryptStatus: Codable, Hashable, Sendable {
    case notListed              // pas de page pour cet id
    case version(String)        // dernière version déchiffrée disponible
    case unreadable             // page lue mais pas de version trouvée (site changé ?)
}

/// Résultat complet pour une app installée.
struct UpdateStatus: Codable, Hashable, Sendable {
    let bundleId: String
    let installedVersion: String
    let checkedAt: Date
    let store: StoreInfo?
    let decrypt: DecryptStatus?
    let error: String?

    /// L'App Store a une version plus récente que celle installée.
    var storeIsNewer: Bool {
        guard let store else { return false }
        return VersionCompare.isNewer(store.version, than: installedVersion)
    }

    /// decrypt.day a une version plus récente que celle installée.
    var decryptedIsNewer: Bool {
        if case .version(let v)? = decrypt { return VersionCompare.isNewer(v, than: installedVersion) }
        return false
    }

    /// decrypt.day est au niveau de l'App Store.
    var decryptedIsCurrent: Bool {
        guard let store, case .version(let v)? = decrypt else { return false }
        return !VersionCompare.isNewer(store.version, than: v)
    }

    enum Badge: Hashable {
        case upToDate
        case decryptedAvailable(String)   // version déchiffrée plus récente, prête
        case waitingDecrypt(String)       // App Store plus récent, pas encore déchiffré
        case notOnStore
        case failed
    }

    var badge: Badge {
        if error != nil, store == nil { return .failed }
        guard let store else { return .notOnStore }
        if decryptedIsNewer, case .version(let v)? = decrypt { return .decryptedAvailable(v) }
        if storeIsNewer { return .waitingDecrypt(store.version) }
        return .upToDate
    }
}

enum VersionCompare {
    /// Compare des versions « 9.1.94 » numériquement, segment par segment.
    static func isNewer(_ a: String, than b: String) -> Bool {
        compare(a, b) == .orderedDescending
    }

    static func compare(_ a: String, _ b: String) -> ComparisonResult {
        let pa = parts(a), pb = parts(b)
        let n = max(pa.count, pb.count)
        for i in 0..<n {
            let x = i < pa.count ? pa[i] : 0
            let y = i < pb.count ? pb[i] : 0
            if x != y { return x < y ? .orderedAscending : .orderedDescending }
        }
        return .orderedSame
    }

    private static func parts(_ s: String) -> [Int] {
        s.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
    }
}

/// Vérifie App Store puis decrypt.day. Résultats gardés 1 h sur disque (Documents/updates.json).
enum UpdateChecker {
    static let cacheLifetime: TimeInterval = 3600
    private static let lock = NSLock()

    private static var cacheURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("updates.json")
    }

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20
        config.httpAdditionalHeaders = [
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Accept-Language": "fr-CA,fr;q=0.9,en;q=0.8"
        ]
        return URLSession(configuration: config)
    }()

    // MARK: - Cache

    static func cached() -> [String: UpdateStatus] {
        lock.lock(); defer { lock.unlock() }
        return loadCache()
    }

    private static func loadCache() -> [String: UpdateStatus] {
        guard let data = try? Data(contentsOf: cacheURL) else { return [:] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([String: UpdateStatus].self, from: data)) ?? [:]
    }

    private static func store(_ status: UpdateStatus) {
        lock.lock(); defer { lock.unlock() }
        var all = loadCache()
        all[status.bundleId] = status
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(all) {
            try? data.write(to: cacheURL, options: .atomic)
        }
    }

    static func clearCache() {
        lock.lock(); defer { lock.unlock() }
        try? FileManager.default.removeItem(at: cacheURL)
    }

    // MARK: - Vérification

    /// Vérifie une app. `force` ignore le cache.
    static func check(_ app: InstalledApp, force: Bool = false) async -> UpdateStatus {
        if !force, let hit = cached()[app.bundleId],
           hit.installedVersion == app.version,
           Date().timeIntervalSince(hit.checkedAt) < cacheLifetime {
            return hit
        }

        var storeInfo: StoreInfo?
        var decrypt: DecryptStatus?
        var errorText: String?

        do {
            storeInfo = try await lookupStore(bundleId: app.bundleId)
        } catch {
            errorText = "App Store : " + error.localizedDescription
        }

        if let storeInfo {
            do {
                decrypt = try await lookupDecryptDay(trackId: storeInfo.trackId)
            } catch {
                errorText = "decrypt.day : " + error.localizedDescription
            }
        }

        let status = UpdateStatus(bundleId: app.bundleId, installedVersion: app.version, checkedAt: Date(),
                                  store: storeInfo, decrypt: decrypt, error: errorText)
        store(status)
        return status
    }

    /// Vérifie plusieurs apps en parallèle (4 à la fois), résultats livrés au fur et à mesure.
    static func checkAll(_ apps: [InstalledApp], force: Bool = false,
                         onEach: @escaping @MainActor @Sendable (UpdateStatus) -> Void) async {
        let targets = apps.filter { !$0.isSelf }
        await withTaskGroup(of: Void.self) { group in
            var index = 0
            while index < targets.count, index < 4 {
                let app = targets[index]
                index += 1
                group.addTask {
                    let status = await check(app, force: force)
                    await onEach(status)
                }
            }
            while await group.next() != nil {
                guard index < targets.count else { continue }
                let app = targets[index]
                index += 1
                group.addTask {
                    let status = await check(app, force: force)
                    await onEach(status)
                }
            }
        }
    }

    // MARK: - App Store

    private struct LookupResponse: Decodable {
        struct Result: Decodable {
            let trackId: Int
            let trackName: String
            let version: String
            let currentVersionReleaseDate: String?
            let releaseNotes: String?
            let trackViewUrl: String
            let artworkUrl100: String?
        }
        let resultCount: Int
        let results: [Result]
    }

    static func lookupStore(bundleId: String) async throws -> StoreInfo? {
        let region = Locale.current.region?.identifier.lowercased() ?? "ca"
        var countries: [String] = []
        for c in [region, "us", "ca", "gb"] where !countries.contains(c) { countries.append(c) }

        for country in countries {
            var comps = URLComponents(string: "https://itunes.apple.com/lookup")!
            comps.queryItems = [
                URLQueryItem(name: "bundleId", value: bundleId),
                URLQueryItem(name: "country", value: country),
                URLQueryItem(name: "t", value: String(Int(Date().timeIntervalSince1970)))  // casse le cache CDN
            ]
            let (data, response) = try await session.data(from: comps.url!)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw JacIPAError.message("réponse HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
            }
            let decoded = try JSONDecoder().decode(LookupResponse.self, from: data)
            guard let r = decoded.results.first else { continue }
            let date = r.currentVersionReleaseDate.flatMap { ISO8601DateFormatter().date(from: $0) }
            return StoreInfo(trackId: r.trackId, name: r.trackName, version: r.version, releaseDate: date,
                             notes: r.releaseNotes, storeURL: URL(string: r.trackViewUrl) ?? comps.url!,
                             artworkURL: r.artworkUrl100.flatMap(URL.init(string:)))
        }
        return nil
    }

    // MARK: - decrypt.day

    /// Lit la page https://decrypt.day/app/id<trackId> et en sort la version affichée.
    /// Pas d'API publique : on cherche « Version » suivi d'un numéro dans le texte de la page.
    static func lookupDecryptDay(trackId: Int) async throws -> DecryptStatus {
        let url = URL(string: "https://decrypt.day/app/id\(trackId)")!
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse else { throw JacIPAError.message("pas de réponse") }
        if http.statusCode == 404 { return .notListed }
        guard (200..<300).contains(http.statusCode) else {
            throw JacIPAError.message("réponse HTTP \(http.statusCode)")
        }
        guard let html = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            return .unreadable
        }
        // Redirigé vers la page de recherche / demande = pas listé.
        if let finalURL = http.url, finalURL.path.hasPrefix("/request") || finalURL.path == "/" || finalURL.path == "/home" {
            return .notListed
        }
        if let v = extractVersion(fromHTML: html) { return .version(v) }
        let lower = html.lowercased()
        if lower.contains("not found") || (lower.contains("request decrypt") && !lower.contains("download")) {
            return .notListed
        }
        return .unreadable
    }

    /// HTML → texte, puis premier numéro de version qui suit le mot « Version ».
    static func extractVersion(fromHTML html: String) -> String? {
        var text = html
        for pattern in ["<script[\\s\\S]*?</script>", "<style[\\s\\S]*?</style>", "<[^>]+>"] {
            text = text.replacingOccurrences(of: pattern, with: " ", options: .regularExpression)
        }
        text = text.replacingOccurrences(of: "&nbsp;", with: " ")
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)

        // Zone principale : avant « Similar Apps » / « Trending » pour ne pas lire la version d'une autre app.
        for marker in ["Similar Apps", "Trending IPAs"] {
            if let r = text.range(of: marker) { text = String(text[..<r.lowerBound]) }
        }

        // D'abord la forme exacte de la fiche (« Version 9.1.94 Updated at … »), sinon n'importe quel
        // « Version x.y » (le descriptif de l'app peut contenir le mot, d'où l'ordre).
        let patterns = [
            "(?i)\\bVersion\\b\\s*:?\\s*v?(\\d+(?:\\.\\d+)*[A-Za-z0-9._-]*)\\s+Updated",
            "(?i)\\bVersion\\b\\s*:?\\s*v?(\\d+(?:\\.\\d+)+[A-Za-z0-9._-]*)"
        ]
        for p in patterns {
            if let regex = try? NSRegularExpression(pattern: p),
               let m = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
               let r = Range(m.range(at: 1), in: text) {
                return String(text[r]).trimmingCharacters(in: CharacterSet(charactersIn: ".-_"))
            }
        }
        return nil
    }
}
