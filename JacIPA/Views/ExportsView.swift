import SwiftUI

struct ExportsView: View {
    enum Mode: String, CaseIterable, Identifiable {
        case files = "Fichiers"
        case history = "Historique"
        var id: String { rawValue }
    }

    @State private var mode: Mode = .files

    var body: some View {
        NavigationStack {
            Group {
                switch mode {
                case .files:
                    ExportsFolderView(folder: ExportStore.root, title: "Exports", isRoot: true)
                case .history:
                    HistoryView()
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) {
                Picker("Affichage", selection: $mode) {
                    ForEach(Mode.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)
                .padding(.bottom, 8)
                .background(.bar)
            }
            .aboutToolbar()
        }
    }
}

struct ExportsFolderView: View {
    let folder: URL
    let title: String
    var isRoot = false

    @Environment(\.openURL) private var openURL
    @State private var entries: [ExportEntry] = []
    @State private var confirmDeleteAll = false

    private var totalSize: Int64 { entries.reduce(0) { $0 + $1.size } }

    var body: some View {
        List {
            if entries.isEmpty {
                Section {
                    Text("Rien ici pour l'instant.").foregroundStyle(.secondary)
                } footer: {
                    Text("Tout ce que JacIPA produit est aussi visible dans l'app Fichiers : Sur mon iPhone → JacIPA → Exports.")
                }
            } else {
                Section {
                    ForEach(entries) { entry in
                        if entry.isDirectory {
                            NavigationLink {
                                ExportsFolderView(folder: entry.url, title: entry.name)
                            } label: {
                                row(entry, icon: "folder")
                            }
                            .contextMenu { menu(for: entry) }
                        } else {
                            row(entry, icon: icon(for: entry.name))
                                .contextMenu { menu(for: entry) }
                        }
                    }
                    .onDelete { offsets in
                        for i in offsets { ExportStore.delete(entries[i].url) }
                        reload()
                    }
                } header: {
                    Text("\(entries.count) élément(s) · \(totalSize.fileSizeText)")
                } footer: {
                    Text("Glisse vers la gauche ou appui long pour supprimer / partager.")
                }
            }
        }
        .navigationTitle(title)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    ShareLink(item: folder) {
                        Label("Partager le dossier", systemImage: "square.and.arrow.up")
                    }
                    if let url = ExportStore.filesAppURL {
                        Button {
                            openURL(url)
                        } label: {
                            Label("Ouvrir dans Fichiers", systemImage: "folder")
                        }
                    }
                    Divider()
                    Button(role: .destructive) {
                        confirmDeleteAll = true
                    } label: {
                        Label(isRoot ? "Tout supprimer" : "Supprimer ce dossier", systemImage: "trash")
                    }
                    .disabled(entries.isEmpty)
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .confirmationDialog(isRoot ? "Supprimer tous les exports ?" : "Supprimer tout le contenu de \(title) ?",
                            isPresented: $confirmDeleteAll, titleVisibility: .visible) {
            Button("Supprimer", role: .destructive) {
                for entry in entries { ExportStore.delete(entry.url) }
                reload()
            }
        } message: {
            Text("\(entries.count) élément(s), \(totalSize.fileSizeText). L'historique est conservé.")
        }
        .onAppear(perform: reload)
        .refreshable { reload() }
    }

    @ViewBuilder
    private func menu(for entry: ExportEntry) -> some View {
        ShareLink(item: entry.url) {
            Label("Partager", systemImage: "square.and.arrow.up")
        }
        Button(role: .destructive) {
            ExportStore.delete(entry.url)
            reload()
        } label: {
            Label("Supprimer", systemImage: "trash")
        }
    }

    private func row(_ entry: ExportEntry, icon: String) -> some View {
        HStack {
            Image(systemName: icon).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 3) {
                Text(entry.name).font(.body.monospaced()).lineLimit(1)
                Text(entry.size.fileSizeText + " · " + entry.date.formatted(date: .abbreviated, time: .shortened))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !entry.isDirectory {
                ShareLink(item: entry.url) {
                    Image(systemName: "square.and.arrow.up")
                }
                .buttonStyle(.borderless)
            }
        }
    }

    private func icon(for name: String) -> String {
        let lower = name.lowercased()
        if lower.hasSuffix(".dylib") { return "puzzlepiece.extension" }
        if lower.hasSuffix(".ipa") { return "app.badge.checkmark" }
        if lower.hasSuffix(".plist") { return "list.bullet.rectangle" }
        if lower.hasSuffix(".txt") { return "doc.text" }
        return "doc"
    }

    private func reload() {
        entries = ExportStore.list(folder)
    }
}

/// Journal des opérations réussies (Deb → dylib, Extraire, Nettoyer, Injecter).
struct HistoryView: View {
    @State private var entries: [HistoryEntry] = []
    @State private var confirmClear = false

    var body: some View {
        List {
            if entries.isEmpty {
                Section {
                    Text("Aucune opération pour l'instant.").foregroundStyle(.secondary)
                } footer: {
                    Text("Chaque Deb → dylib, extraction, nettoyage ou injection réussi s'inscrit ici.")
                }
            }
            ForEach(entries) { entry in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Label(entry.tool, systemImage: icon(for: entry.tool))
                            .font(.subheadline.bold())
                        Spacer()
                        Text(entry.date.formatted(date: .abbreviated, time: .shortened))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text(entry.source + " → " + entry.output)
                        .font(.footnote.monospaced())
                        .lineLimit(2)
                    if !entry.details.isEmpty {
                        DisclosureGroup {
                            ForEach(Array(entry.details.enumerated()), id: \.offset) { _, d in
                                Text(d).font(.caption).foregroundStyle(.secondary)
                            }
                        } label: {
                            Text("Détails (\(entry.details.count))").font(.caption)
                        }
                    }
                }
                .padding(.vertical, 2)
            }
            .onDelete { offsets in
                ExportStore.removeHistory(ids: Set(offsets.map { entries[$0].id }))
                reload()
            }
        }
        .navigationTitle("Historique")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Effacer", role: .destructive) { confirmClear = true }
                    .disabled(entries.isEmpty)
            }
        }
        .confirmationDialog("Effacer tout l'historique ?", isPresented: $confirmClear, titleVisibility: .visible) {
            Button("Effacer", role: .destructive) {
                ExportStore.clearHistory()
                reload()
            }
        } message: {
            Text("Les fichiers dans Exports ne sont pas touchés.")
        }
        .onAppear(perform: reload)
        .refreshable { reload() }
    }

    private func icon(for tool: String) -> String {
        switch tool {
        case "Deb → dylib": return "shippingbox"
        case "Extraire": return "arrow.down.doc"
        case "Nettoyer": return "sparkles"
        case "Injecter": return "syringe"
        default: return "clock"
        }
    }

    private func reload() {
        entries = ExportStore.history()
    }
}
