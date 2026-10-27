import SwiftUI
import UniformTypeIdentifiers

struct DebView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showPicker = false
    @State private var working = false
    @State private var result: DebResult?
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button {
                        showPicker = true
                    } label: {
                        Label("Choisir un fichier .deb", systemImage: "doc.badge.plus")
                    }
                    .disabled(working)

                    if working {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text("Extraction…")
                        }
                    }
                    if let errorText {
                        Text(errorText).foregroundStyle(.red)
                    }
                } footer: {
                    Text("Ouvre un paquet .deb (rootless ou roothide ; gz, xz, lzma, zstd, bz2) et sort les .dylib, .bundle et filtres .plist prêts pour LiveContainer.")
                }

                if let result {
                    resultSections(result)
                }
            }
            .navigationTitle("Deb → dylib")
            .aboutToolbar()
            .fileImporter(isPresented: $showPicker, allowedContentTypes: [.item], allowsMultipleSelection: false) { res in
                switch res {
                case .success(let urls):
                    if let url = urls.first { run(url) }
                case .failure(let error):
                    errorText = error.localizedDescription
                }
            }
            .onChange(of: model.incomingDeb) { _, newValue in
                if let url = newValue {
                    run(url)
                    model.incomingDeb = nil
                }
            }
        }
    }

    @ViewBuilder
    private func resultSections(_ r: DebResult) -> some View {
        Section("Paquet") {
            LabeledContent("Nom", value: r.packageName)
            if let v = r.version { LabeledContent("Version", value: v) }
            LabeledContent("Dossier", value: "Exports/" + r.exportFolder.lastPathComponent)
        }

        Section("Dylibs (\(r.dylibs.count))") {
            if r.dylibs.isEmpty {
                Text("Aucun .dylib trouvé.").foregroundStyle(.secondary)
            }
            ForEach(r.dylibs) { file in
                fileRow(file)
            }
        }

        if !r.bundles.isEmpty {
            Section("Bundles (ressources)") {
                ForEach(r.bundles, id: \.self) { Text($0).font(.body.monospaced()) }
            }
        }

        if !r.plists.isEmpty {
            Section("Filtres (.plist)") {
                ForEach(r.plists) { fileRow($0) }
            }
        }

        if !r.notes.isEmpty {
            Section("Notes") {
                ForEach(r.notes, id: \.self) { Text($0).font(.footnote) }
            }
        }

        Section {
            Text("Ensuite : LiveContainer → Tweaks → dossier de l'app → + → Fichiers → JacIPA → Exports → le .dylib.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text("Ou : onglet IPA → Injecter un dylib, pour une app tout-en-un.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func fileRow(_ file: ExtractedFile) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text(file.exportedURL.lastPathComponent).font(.body.monospaced())
                Text(Int64(file.size).fileSizeText).font(.caption).foregroundStyle(.secondary)
                if !file.dependencies.isEmpty {
                    Text("Dépend de : " + file.dependencies.map { ($0 as NSString).lastPathComponent }.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ForEach(file.warnings, id: \.self) { w in
                    Text("⚠️ " + w).font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            ShareLink(item: file.exportedURL) {
                Image(systemName: "square.and.arrow.up")
            }
            .buttonStyle(.borderless)
        }
    }

    private func run(_ url: URL) {
        working = true
        errorText = nil
        result = nil
        Task { @MainActor in
            do {
                let local = try ExportStore.importToTemp(url)
                let r = try await DebExtractor.extract(url: local)
                result = r
                var details = r.dylibs.map { $0.exportedURL.lastPathComponent }
                details += r.plists.map { $0.exportedURL.lastPathComponent }
                details += r.bundles
                ExportStore.log(tool: "Deb → dylib", source: local.lastPathComponent,
                                output: r.exportFolder.lastPathComponent, details: details)
            } catch {
                errorText = error.localizedDescription
            }
            working = false
        }
    }
}
