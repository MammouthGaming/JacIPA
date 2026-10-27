import SwiftUI

struct ExportsView: View {
    var body: some View {
        NavigationStack {
            ExportsFolderView(folder: ExportStore.root, title: "Exports")
        }
    }
}

struct ExportsFolderView: View {
    let folder: URL
    let title: String
    @State private var entries: [ExportEntry] = []

    var body: some View {
        List {
            if entries.isEmpty {
                Section {
                    Text("Rien ici pour l'instant.").foregroundStyle(.secondary)
                } footer: {
                    Text("Tout ce que JacIPA produit est aussi visible dans l'app Fichiers : Sur mon iPhone → JacIPA → Exports.")
                }
            }
            ForEach(entries) { entry in
                if entry.isDirectory {
                    NavigationLink {
                        ExportsFolderView(folder: entry.url, title: entry.name)
                    } label: {
                        row(entry, icon: "folder")
                    }
                } else {
                    row(entry, icon: icon(for: entry.name))
                }
            }
            .onDelete { offsets in
                for i in offsets { ExportStore.delete(entries[i].url) }
                reload()
            }
        }
        .navigationTitle(title)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                ShareLink(item: folder) {
                    Image(systemName: "square.and.arrow.up")
                }
            }
        }
        .onAppear(perform: reload)
        .refreshable { reload() }
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
