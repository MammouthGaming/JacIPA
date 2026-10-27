import SwiftUI
import UniformTypeIdentifiers

struct IPAView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showPicker = false
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
                    Text("Dit si l'IPA est déchiffré, liste les tweaks injectés, et peut les extraire ou produire un IPA propre.")
                }

                if let a = analysis {
                    infoSection(a)
                    itemsSection(a)
                    actionsSection(a)
                }

                if let r = actionResult {
                    Section("Résultat") {
                        LabeledContent("Sortie", value: "Exports/" + r.outputURL.lastPathComponent)
                        ForEach(r.details, id: \.self) { Text($0).font(.footnote) }
                        ForEach(r.warnings, id: \.self) { Text("⚠️ " + $0).font(.footnote).foregroundStyle(.orange) }
                        ShareLink(item: r.outputURL) {
                            Label("Partager", systemImage: "square.and.arrow.up")
                        }
                    }
                }
            }
            .navigationTitle("IPA")
            .fileImporter(isPresented: $showPicker, allowedContentTypes: [.item], allowsMultipleSelection: false) { res in
                switch res {
                case .success(let urls):
                    if let url = urls.first { analyze(url) }
                case .failure(let error):
                    errorText = error.localizedDescription
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
                ForEach(a.warnings, id: \.self) { Text("⚠️ " + $0).font(.footnote).foregroundStyle(.orange) }
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
        Section("Actions") {
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
