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
                    Text("Rien ici pour l'instant.").fo