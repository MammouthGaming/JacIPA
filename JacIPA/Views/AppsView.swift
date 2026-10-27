import SwiftUI
import UniformTypeIdentifiers

/// Onglet « Apps » : les applications installées dans LiveContainer, avec vérification
/// App Store → decrypt.day et mise à jour en gardant les tweaks.
struct AppsView: View {
    @State private var apps: [InstalledApp] = []
    @State private var statuses: [String: UpdateStatus] = [:]
    @State private var scanning = false
    @State private var checking = false
    @State private var errorText: String?
    @State private var showFolderPicker = false
    @State private var folderMode: FolderMode = .none

    enum FolderMode { case none, automatic, bookmark }

    var body: some View {
        NavigationStack {
            List {
                headerSection
                if !apps.isEmpty { appsSection }
            }
            .navigationTitle("Apps")
            .aboutToolbar()
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        checkAll(force: true)
                    } label: {
                        if checking { ProgressView() } else { Image(systemName: "arrow.triangle.2.circlepath") }
                    }
                    .disabled(apps.isEmpty || checking || scanning)
                    .accessibilityLabel("Vérifier les mises à jour")
                }
            }
            .refreshable { await rescan(thenCheck: true, force: true) }
            .fileImporter(isPresented: $showFolderPicker, allowedContentTypes: [.folder], allowsMultipleSelection: false) { res in
                switch res {
                case .success(let urls):
                    if let url = urls.first { chooseFolder(url) }
                case .failure(let error):
                    errorText = error.localizedDescription
                }
            }
            .task {
                statuses = UpdateChecker.cached()
                await rescan(thenCheck: true, force: false)
            }
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var headerSection: some View {
        Section {
            if scanning {
                HStack(spacing: 12) { ProgressView(); Text("Lecture de la bibliothèque…") }
            }
            switch folderMode {
            case .automatic:
                Label("Bibliothèque LiveContainer trouvée automatiquement", systemImage: "checkmark.circle")
                    .foregroundStyle(.green)
            case .bookmark:
                Label("Dossier Applications choisi manuellement", systemImage: "folder.badge.person.crop")
                Button("Oublier ce dossier", role: .destructive) {
                    InstalledApps.forgetBookmark()
                    Task { await rescan(thenCheck: false, force: false) }
                }
            case .none:
                if !scanning {
                    Label("Bibliothèque introuvable", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }
            if folderMode != .automatic {
                Button {
                    showFolderPicker = true
                } label: {
                    Label("Choisir le dossier Applications de LiveContainer…", systemImage: "folder.badge.plus")
                }
            }
            if let errorText {
                Text(errorText).foregroundStyle(.red)
            }
        } footer: {
            Text("Pour chaque app : version installée, dernière version sur l'App Store, et si decrypt.day a déjà l'IPA déchiffré. Tire vers le bas pour tout revérifier.")
        }
    }

    private var appsSection: some View {
        Section("Applications (\(apps.count))") {
            ForEach(apps) { app in
                NavigationLink {
                    InstalledAppDetailView(app: app, status: statuses[app.bundleId]) { status in
                        statuses[status.bundleId] = status
                    }
                } label: {
                    InstalledAppRow(app: app, status: statuses[app.bundleId])
                }
            }
        }
    }

    // MARK: - Actions

    @MainActor
    private func rescan(thenCheck: Bool, force: Bool) async {
        scanning = true
        errorText = nil
        do {
            apps = try await InstalledApps.scan()
            folderMode = InstalledApps.bookmarkedFolder != nil ? .bookmark : (InstalledApps.isAutomatic ? .automatic : .none)
        } catch {
            apps = []
            folderMode = .none
            errorText = error.localizedDescription
        }
        scanning = false
        if thenCheck, !apps.isEmpty { await runCheck(force: force) }
    }

    private func chooseFolder(_ url: URL) {
        guard InstalledApps.isApplicationsFolder(url) else {
            errorText = "\(url.lastPathComponent) ne ressemble pas au dossier Applications de LiveContainer (il doit contenir des dossiers avec un .app dedans)."
            return
        }
        do {
            try InstalledApps.saveBookmark(for: url)
            Task { await rescan(thenCheck: true, force: false) }
        } catch {
            errorText = error.localizedDescription
        }
    }

    private func checkAll(force: Bool) {
        Task { await runCheck(force: force) }
    }

    @MainActor
    private func runCheck(force: Bool) async {
        guard !checking else { return }
        checking = true
        await UpdateChecker.checkAll(apps, force: force) { status in
            statuses[status.bundleId] = status
        }
        checking = false
    }
}

// MARK: - Ligne

struct InstalledAppRow: View {
    let app: InstalledApp
    let status: UpdateStatus?

    var body: some View {
        HStack(spacing: 12) {
            AppIconImage(url: app.iconURL, size: 44)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(app.name).lineLimit(1)
                    if app.isSelf {
                        Text("moi").font(.caption2.bold()).foregroundStyle(.secondary)
                    }
                }
                Text(app.versionText + (app.tweaks.isEmpty ? "" : " · \(app.tweaks.count) tweak\(app.tweaks.count > 1 ? "s" : "")"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            if !app.isSelf { UpdateBadge(status: status) }
        }
    }
}

struct UpdateBadge: View {
    let status: UpdateStatus?

    var body: some View {
        let (text, color): (String, Color) = {
            guard let status else { return ("…", .gray) }
            switch status.badge {
            case .upToDate: return ("À jour", .green)
            case .decryptedAvailable(let v): return ("⬆︎ \(v) déchiffré", .blue)
            case .waitingDecrypt(let v): return ("\(v) · pas déchiffré", .orange)
            case .notOnStore: return ("Hors App Store", .gray)
            case .failed: return ("Erreur", .red)
            }
        }()
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
            .lineLimit(1)
    }
}

/// Icône lue dans le bundle (PNG), sinon un carré générique.
struct AppIconImage: View {
    let url: URL?
    let size: CGFloat
    @State private var image: UIImage?

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                    .fill(Color.gray.opacity(0.25))
                    .overlay(Image(systemName: "app").foregroundStyle(.secondary))
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.22, style: .continuous))
        .task(id: url) {
            guard let url else { image = nil; return }
            image = UIImage(contentsOfFile: url.path)
        }
    }
}

// MARK: - Détail

struct InstalledAppDetailView: View {
    let app: InstalledApp
    let initialStatus: UpdateStatus?
    let onStatus: (UpdateStatus) -> Void

    init(app: InstalledApp, status: UpdateStatus?, onStatus: @escaping (UpdateStatus) -> Void) {
        self.app = app
        self.initialStatus = status
        self.onStatus = onStatus
    }

    /// Résultat d'un « Revérifier » fait ici, sinon celui reçu de la liste.
    @State private var refreshed: UpdateStatus?
    private var status: UpdateStatus? { refreshed ?? initialStatus }

    @State private var checking = false
    @State private var showNotes = false
    @State private var showPicker = false
    @State private var working = false
    @State private var workingLabel = ""
    @State private var errorText: String?
    @State private var result: IPAActionResult?

    var body: some View {
        List {
            Section {
                HStack(spacing: 14) {
                    AppIconImage(url: app.iconURL, size: 64)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(app.name).font(.title3.bold())
                        Text(app.bundleId).font(.caption.monospaced()).foregroundStyle(.secondary)
                        Text("Installée : \(app.versionText) · \(app.size.fileSizeText)").font(.caption)
                    }
                }
            }

            if !app.isSelf { updateSection }
            tweaksSection
            if !app.isSelf { actionsSection }

            if let r = result {
                Section("Résultat") {
                    LabeledContent("Sortie", value: "Exports/" + r.outputURL.lastPathComponent)
                    ForEach(Array(r.details.enumerated()), id: \.offset) { _, d in
                        Text(d).font(.footnote)
                    }
                    ForEach(Array(r.warnings.enumerated()), id: \.offset) { _, w in
                        Text("⚠️ " + w).font(.footnote).foregroundStyle(.orange)
                    }
                    ShareLink(item: r.outputURL) {
                        Label("Envoyer à LiveContainer…", systemImage: "square.and.arrow.up")
                    }
                    if let files = ExportStore.filesAppURL {
                        Link(destination: files) {
                            Label("Ouvrir dans Fichiers", systemImage: "folder")
                        }
                    }
                }
            }
        }
        .navigationTitle(app.name)
        .navigationBarTitleDisplayMode(.inline)
        .fileImporter(isPresented: $showPicker, allowedContentTypes: [.item], allowsMultipleSelection: false) { res in
            switch res {
            case .success(let urls):
                if let url = urls.first { update(with: url) }
            case .failure(let error):
                errorText = error.localizedDescription
            }
        }
    }

    // MARK: Sections

    @ViewBuilder
    private var updateSection: some View {
        Section {
            if let s = status {
                if let store = s.store {
                    LabeledContent("App Store", value: store.version)
                    if let date = store.releaseDate {
                        LabeledContent("Publiée", value: date.formatted(date: .abbreviated, time: .omitted))
                    }
                    decryptRow(s)
                    if let notes = store.notes, !notes.isEmpty {
                        DisclosureGroup("Nouveautés", isExpanded: $showNotes) {
                            Text(notes).font(.footnote)
                        }
                    }
                    Link(destination: store.decryptDayURL) {
                        Label("Voir sur decrypt.day", systemImage: "lock.open")
                    }
                    Link(destination: store.storeURL) {
                        Label("Voir sur l'App Store", systemImage: "bag")
                    }
                } else if s.error == nil {
                    Text("Pas sur l'App Store (app sideloadée ou retirée).").foregroundStyle(.secondary)
                }
                if let e = s.error {
                    Text("⚠️ " + e).font(.footnote).foregroundStyle(.orange)
                }
                Text("Vérifié " + s.checkedAt.formatted(.relative(presentation: .named)))
                    .font(.caption).foregroundStyle(.secondary)
            } else if !checking {
                Text("Pas encore vérifié.").foregroundStyle(.secondary)
            }
            Button {
                check()
            } label: {
                HStack {
                    Label("Revérifier maintenant", systemImage: "arrow.triangle.2.circlepath")
                    if checking { Spacer(); ProgressView() }
                }
            }
            .disabled(checking)
        } header: {
            HStack {
                Text("Mise à jour")
                Spacer()
                UpdateBadge(status: status)
            }
        }
    }

    @ViewBuilder
    private func decryptRow(_ s: UpdateStatus) -> some View {
        switch s.decrypt {
        case .version(let v)?:
            let newer = VersionCompare.isNewer(v, than: app.version)
            LabeledContent("decrypt.day") {
                Text(v + (s.decryptedIsCurrent ? " ✓" : ""))
                    .foregroundStyle(newer ? .blue : .primary)
            }
        case .notListed?:
            LabeledContent("decrypt.day", value: "Pas listée")
        case .unreadable?:
            LabeledContent("decrypt.day", value: "Page illisible")
        case nil:
            EmptyView()
        }
    }

    @ViewBuilder
    private var tweaksSection: some View {
        Section {
            if app.tweaks.isEmpty && app.frameworks.isEmpty {
                Text("Aucun tweak injecté.").foregroundStyle(.secondary)
            }
            ForEach(app.tweaks, id: \.self) { name in
                Label(name, systemImage: "puzzlepiece.extension").font(.body.monospaced())
            }
            ForEach(app.frameworks, id: \.self) { name in
                Label(name, systemImage: "shippingbox").font(.body.monospaced())
            }
        } header: {
            Text("Tweaks dans Frameworks/ (\(app.tweaks.count + app.frameworks.count))")
        } footer: {
            if !app.tweaks.isEmpty {
                Text("Ils seront réinjectés tels quels dans le nouvel IPA.")
            }
        }
    }

    @ViewBuilder
    private var actionsSection: some View {
        Section {
            Button {
                showPicker = true
            } label: {
                Label(app.tweaks.isEmpty ? "Mettre à jour avec un nouvel IPA…" : "Mettre à jour en gardant les tweaks…",
                      systemImage: "arrow.up.doc")
            }
            .disabled(working)
            if working {
                HStack(spacing: 12) { ProgressView(); Text(workingLabel) }
            }
            if let errorText {
                Text(errorText).foregroundStyle(.red)
            }
        } header: {
            Text("Actions")
        } footer: {
            Text("1. Télécharge le nouvel IPA déchiffré (decrypt.day). 2. Choisis-le ici : JacIPA vérifie que c'est la même app, réinjecte tes tweaks, et te donne l'IPA. 3. Partage-le vers LiveContainer : même bundle, il remplace l'app en gardant ses données.")
        }
    }

    // MARK: Actions

    private func check() {
        checking = true
        Task { @MainActor in
            let s = await UpdateChecker.check(app, force: true)
            refreshed = s
            onStatus(s)
            checking = false
        }
    }

    private func update(with url: URL) {
        working = true
        workingLabel = "Analyse du nouvel IPA…"
        errorText = nil
        result = nil
        Task { @MainActor in
            do {
                let local = try ExportStore.importToTemp(url)
                let analysis = try await IPAInspector.analyze(url: local)
                guard analysis.bundleId == app.bundleId else {
                    throw JacIPAError.message("Ce n'est pas la même app : l'IPA est \(analysis.appName) (\(analysis.bundleId)), l'app installée est \(app.bundleId).")
                }
                if analysis.encrypted == true {
                    throw JacIPAError.message("Cet IPA est chiffré (FairPlay) : il ne se lancera pas dans LiveContainer. Prends la version déchiffrée.")
                }
                let newVersion = analysis.version.split(separator: " ").first.map(String.init) ?? analysis.version
                if !newVersion.isEmpty, VersionCompare.isNewer(app.version, than: newVersion) {
                    throw JacIPAError.message("L'IPA choisi (\(newVersion)) est plus vieux que la version installée (\(app.version)).")
                }

                let files = app.injectableURLs
                if files.isEmpty {
                    // Rien à garder : on copie l'IPA tel quel dans Exports pour le partager.
                    let out = ExportStore.uniqueFile(named: ExportStore.sanitize(analysis.appName) + "-\(newVersion).ipa")
                    try FileManager.default.copyItem(at: local, to: out)
                    ExportStore.log(tool: "Mettre à jour", source: local.lastPathComponent, output: out.lastPathComponent,
                                    details: ["Aucun tweak à réinjecter"])
                    result = IPAActionResult(outputURL: out, details: ["Aucun tweak dans l'app installée : IPA copié tel quel."],
                                             warnings: [])
                } else {
                    workingLabel = "Réinjection de \(files.count) fichier(s)…"
                    var r = try await IPAInspector.inject(analysis, files: files)
                    r = IPAActionResult(outputURL: r.outputURL,
                                        details: ["\(app.versionText) → \(newVersion)"] + r.details,
                                        warnings: r.warnings)
                    result = r
                }
            } catch {
                errorText = error.localizedDescription
            }
            working = false
        }
    }
}
