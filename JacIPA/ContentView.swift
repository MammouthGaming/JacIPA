import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        TabView(selection: $model.tab) {
            AppsView()
                .tabItem { Label("Apps", systemImage: "square.grid.2x2") }
                .tag(AppModel.Tab.apps)
            DebView()
                .tabItem { Label("Deb", systemImage: "shippingbox") }
                .tag(AppModel.Tab.deb)
            IPAView()
                .tabItem { Label("IPA", systemImage: "app.badge.checkmark") }
                .tag(AppModel.Tab.ipa)
            ExportsView()
                .tabItem { Label("Exports", systemImage: "folder") }
                .tag(AppModel.Tab.exports)
        }
    }
}
