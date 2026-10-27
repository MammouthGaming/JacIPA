import SwiftUI
import UniformTypeIdentifiers

struct IPAView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showPicker = false
    @State private var showInjectPicker = false
    @State private var working = false
    @State private var workingLabel = ""
    @State private var analysis: IPAAnalysis?
    @State private var selected = Set<String>()
    @State private var errorText: String?
    @State private var actionResult: IPAActionResult?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button {
                        showPicker = true
                    } label: {
                        Label("Choisir un fichier .ipa", systemImage: "doc.badge.plus")
                    }
                    .disabled(working)

                    if working {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text(workingLabel)
                        }
                    }
                    if let errorText {
                        Text(errorText).foregroundStyle(.red)
                    }
                } footer: {
                    Text("Dit si l'IPA est déchiffré, liste les tweaks injectés, et peut les extraire, les retirer, ou en injecter un nouveau.")
                }

                if let a = analysis {
                    infoSection(a)
                    itemsSection(a)
                    actionsSection(a)
                }

                if let r = actionResult {
                    Section("Résultat") {
                        LabeledContent("Sortie", value: "Exports/" + r.outputURL.lastPathComponent)
                        ForEach(Array(r.details.enumerated()), id: \.offset) { _, d in
                            Text(d).font(.footnote)
                        }
                        ForEach(Array(r.warnings.enumerated()), id: \.offset) { _, w in
                            Text("⚠️ " + w).font(.footnote).foregroundStyle(.orange)
                        }
                        ShareLink(item: r.outputURL) {
                            Label("Partager", systemImage: "square.and.arrow.up")
                        }
                    }
                }
            }
            .navigationTitle("IPA")
            .aboutToolbar()
            .fileImporter(isPresented: $showPicker, allowedContentTypes: [.item], allowsMultipleSelection: false) { res in
                switch res {
                case .success(let urls):
                    if let url = urls.first { analyze(url) }
                case .failure(let error):
                    errorText = error.localizedDescription
                }
            }
            .sheet(isPresented: $showInjectPicker) {
                if let a = analysis {
                    InjectPickerView(appName: a.appName) { files in
                        runAction(label: "Injection…") { try await IPAInspector.inject(a, files: files) }
                    }
                }
            }
            .onChange(of: model.incomingIPA) { _, newValue in
                if let url = newValue {
                    analyze(url)
                    model.incomingIPA = nil
                }
            }
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private func infoSection(_ a: IPAAnalysis) -> some View {
        Section("Application") {
            LabeledContent("Nom", value: a.appName)
            LabeledContent("Bundle", value: a.bundleId)
            LabeledContent("Version", value: a.version.isEmpty ? "?" : a.version)
            LabeledContent("Binaire", value: a.executable)
            LabeledContent("Architectures", value: a.archs.isEmpty ? "?" : a.archs)
            LabeledContent("Fichiers", value: "\(a.entryCount)")
            encryptionRow(a.encrypted)
        }
        if !a.warnings.isEmpty {
            Section("Avertissements") {
                ForEach(Array(a.warnings.enumerated()), id: \.offset) { _, w in
                    Text("⚠️ " + w).font(.footnote).foregroundStyle(.orange)
                }
            }
        }
    }

    @ViewBuilder
    private func encryptionRow(_ encrypted: Bool?) -> some View {
        switch encrypted {
        case .some(true):
            Label("Chiffré (FairPlay) : ne marchera pas dans LiveContainer", systemImage: "lock.fill")
                .foregroundStyle(.red)
        case .some(false):
            Label("Déchiffré : OK pour LiveContainer", systemImage: "lock.open.fill")
                .foregroundStyle(.green)
        case .none:
            Label("Chiffrement inconnu", systemImage: "questionmark.circle")
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func itemsSection(_ a: IPAAnalysis) -> some View {
        Section {
            if a.items.isEmpty {
                Text("Aucun .dylib ni .framework dans l'app.").foregroundStyle(.secondary)
            }
            ForEach(a.items) { item in
                Toggle(isOn: binding(for: item.id)) {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 8) {
                            Text(item.name).font(.body.monospaced()).lineLimit(1)
                            Spacer(minLength: 0)
                            Text(item.kind.rawValue)
                                .font(.caption2.bold())
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(color(for: item.kind).opacity(0.18), in: Capsule())
                                .foregroundStyle(color(for: item.kind))
                        }
                        Text(item.reason + " · " + Int64(item.size).fileSizeText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } header: {
            Text("Frameworks et dylibs (\(a.items.count))")
        } footer: {
            Text("Coche ce qu'il faut extraire ou retirer. Les tweaks et dépendances sont cochés d'office.")
        }
    }

    @ViewBuilder
    private func actionsSection(_ a: IPAAnalysis) -> some View {
        let chosen = a.items.filter { selected.contains($0.id) }
        Section {
            Button {
                runAction(label: "Extraction…") { try await IPAInspector.extract(a, items: chosen) }
            } label: {
                Label("Extraire la sélection (\(chosen.count))", systemImage: "arrow.down.doc")
            }
            .disabled(chosen.isEmpty || working)

            Button {
                runAction(label: "Nettoyage de l'IPA…") { try await IPAInspector.clean(a, remove: chosen) }
            } label: {
                Label("Nettoyer l'IPA (retirer la sélection)", systemImage: "sparkles")
            }
            .disabled(chosen.isEmpty || working)

            Button {
                showInjectPicker = true
            } label: {
                Label("Injecter un dylib dans l'IPA…", systemImage: "syringe")
            }
            .disabled(working || a.encrypted == true)
        } header: {
            Text("Actions")
        } footer: {
            if a.encrypted == true {
                Text("Injection désactivée : l'IPA est chiffré, il ne se lancerait pas dans LiveContainer.")
            } else {
                Text("Injecter : choisis un .dylib sorti par Deb → dylib (ex. GTok) pour obtenir un IPA tout-en-un, à importer tel quel dans LiveContainer.")
            }
        }
    }

    // MARK: - Helpers

    private func binding(for id: String) -> Binding<Bool> {
        Binding(
            get: { selected.contains(id) },
            set: { on in
                if on { selected.insert(id) } else { selected.remove(id) }
            }
        )
    }

    private func color(for kind: FrameworkKind) -> Color {
        switch kind {
        case .tweak: return .red
        case .dependency: return .orange
        case .normal: return .gray
        }
    }

    private func analyze(_ url: URL) {
        working = true
        workingLabel = "Analyse…"
        errorText = nil
        analysis = nil
        actionResult = nil
        selected = []
        Task { @MainActor in
            do {
                let local = try ExportStore.importToTemp(url)
                let a = try await IPAInspector.analyze(url: local)
                analysis = a
                selected = Set(a.suspicious.map(\.id))
            } catch {
                errorText = error.localizedDescription
            }
            working = false
        }
    }

    private func runAction(label: String, _ op: @escaping () async throws -> IPAActionResult) {
        working = true
        workingLabel = label
        errorText = nil
        actionResult = nil
        Task { @MainActor in
            do {
                actionResult = try await op()
            } catch {
                errorText = error.localizedDescription
            }
            working = false
        }
    }
}

/// Feuille « Injecter » : .dylib / .framework déjà dans Exports, plus des fichiers pris dans Fichiers.
struct InjectPickerView: View {
    let appName: String
    let onConfirm: ([URL]) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var entries: [ExportEntry] = []
    @State private var selected = Set<String>()
    @State private var extra: [URL] = []
    @State private var showPicker = false
    @State private var errorText: String?

    private var count: Int { selected.count + extra.count }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if entries.isEmpty {
                        Text("Aucun .dylib dans Exports. Passe d'abord par Deb → dylib, ou choisis un fichier plus bas.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(entries) { entry in
                        Toggle(isOn: binding(for: entry.id)) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(entry.name).font(.body.monospaced()).lineLimit(1)
                                Text(entry.url.deletingLastPathComponent().lastPathComponent + " · " + entry.size.fileSizeText)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Text("Depuis Exports")
                } footer: {
                    Text("Le .dylib est copié dans Frameworks/ et le binaire principal reçoit une commande de chargement (comme insert_dylib). Si le tweak a besoin de CydiaSubstrate et que l'app plante, ajoute CydiaSubstrate.framework depuis Fichiers → LiveContainer → Tweaks.")
                }

                Section("Autres fichiers") {
                    ForEach(extra, id: \.self) { url in
                        HStack {
                            Image(systemName: url.lastPathComponent.hasSuffix(".framework") ? "shippingbox" : "puzzlepiece.extension")
                                .foregroundStyle(.tint)
                            Text(url.lastPathComponent).font(.body.monospaced()).lineLimit(1)
                        }
                    }
                    .onDelete { offsets in extra.remove(atOffsets: offsets) }

                    Button {
                        showPicker = true
                    } label: {
                        Label("Choisir dans Fichiers…", systemImage: "folder.badge.plus")
                    }
                    if let errorText {
                        Text(errorText).font(.footnote).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Injecter dans \(appName)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Injecter (\(count))") { confirm() }
                        .disabled(count == 0)
                }
            }
            .fileImporter(isPresented: $showPicker, allowedContentTypes: [.item, .folder], allowsMultipleSelection: true) { res in
                switch res {
                case .success(let urls):
                    for url in urls {
                        do {
                            let local = try ExportStore.importToTemp(url)
                            if !extra.contains(local) { extra.append(local) }
                        } catch {
                            errorText = error.localizedDescription
                        }
                    }
                case .failure(let error):
                    errorText = error.localizedDescription
                }
            }
            .onAppear { entries = ExportStore.allInjectables() }
        }
    }

    private func binding(for id: String) -> Binding<Bool> {
        Binding(
            get: { selected.contains(id) },
            set: { on in
                if on { selected.insert(id) } else { selected.remove(id) }
            }
        )
    }

    private func confirm() {
        let files = entries.filter { selected.contains($0.id) }.map(\.url) + extra
        dismiss()
        onConfirm(files)
    }
}
