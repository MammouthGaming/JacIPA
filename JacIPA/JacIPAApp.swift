import SwiftUI

@main
struct JacIPAApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onOpenURL { url in model.handle(url) }
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    enum Tab: Hashable { case deb, ipa, exports }

    @Published var tab: Tab = .deb
    @Published var incomingDeb: URL?
    @Published var incomingIPA: URL?

    /// Fichier reçu via « Ouvrir dans JacIPA » (Fichiers, Telegram, AirDrop…).
    func handle(_ url: URL) {
        switch url.pathExtension.lowercased() {
        case "deb":
            incomingDeb = url
            tab = .deb
        case "ipa", "zip":
            incomingIPA = url
            tab = .ipa
        default:
            break
        }
    }
}
