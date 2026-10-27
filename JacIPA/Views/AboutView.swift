import SwiftUI

/// L'icône de l'app (celle d'Assets.xcassets), arrondie comme sur l'écran d'accueil.
struct AppIconView: View {
    var size: CGFloat = 28

    var body: some View {
        Group {
            if let image = AppIconView.image {
                Image(uiImage: image)
                    .renderingMode(.original)
                    .resizable()
                    .scaledToFill()
            } else {
                Image(systemName: "shippingbox.fill")
                    .resizable()
                    .scaledToFit()
                    .padding(size * 0.22)
                    .foregroundStyle(.white)
                    .background(Color.black)
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.2237, style: .continuous))
    }

    /// Xcode compile l'AppIcon en fichiers listés dans CFBundleIcons : on prend le plus grand.
    static let image: UIImage? = {
        if let direct = UIImage(named: "AppIcon") { return direct }
        guard let icons = Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any],
              let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
              let files = primary["CFBundleIconFiles"] as? [String],
              let last = files.last else { return nil }
        return UIImage(named: last)
    }()
}

struct AboutView: View {
    @Environment(\.dismiss) private var dismiss

    private var versionText: String {
        let info = Bundle.main.infoDictionary
        let v = info?["CFBundleShortVersionString"] as? String ?? "?"
        let b = info?["CFBundleVersion"] as? String ?? "?"
        return "Version \(v) (\(b))"
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 12) {
                        AppIconView(size: 96)
                            .shadow(color: .black.opacity(0.25), radius: 8, y: 4)
                        Text("JacIPA").font(.title.bold())
                        Text(versionText).foregroundStyle(.secondary)
                        Text("Dylibs et IPA pour LiveContainer, directement sur l'iPhone.")
                            .font(.footnote)
                            .multilineTextAlignment(.center)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .listRowBackground(Color.clear)
                }

                Section("Outils") {
                    tool("shippingbox", "Deb → dylib",
                         "Sort les .dylib, .bundle et filtres .plist d'un paquet Cydia / Sileo (gz, xz, lzma, zstd, bz2).")
                    tool("magnifyingglass", "Inspecter un IPA",
                         "Dit si l'app est déchiffrée et repère les tweaks déjà injectés.")
                    tool("arrow.down.doc", "Extraire / Nettoyer",
                         "Récupère les tweaks d'un IPA, ou produit un IPA propre sans eux.")
                    tool("syringe", "Injecter",
                         "Ajoute un .dylib dans un IPA : une seule app tout-en-un à importer dans LiveContainer.")
                }

                Section("Liens") {
                    if let url = URL(string: "https://github.com/MammouthGaming/JacIPA") {
                        Link(destination: url) {
                            Label("Code source sur GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
                        }
                    }
                    if let url = URL(string: "https://livecontainer.github.io/docs/guides/tweaks") {
                        Link(destination: url) {
                            Label("LiveContainer : guide des tweaks", systemImage: "book")
                        }
                    }
                }

                Section {
                    Text("Fait par Jacob avec Mammouth AI. Tout en Swift, sans dépendance, 100 % hors ligne : rien ne quitte l'iPhone.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("À propos")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") { dismiss() }
                }
            }
        }
    }

    private func tool(_ icon: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .frame(width: 24)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.bold())
                Text(text).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}

/// Petite icône JacIPA en haut à gauche de chaque onglet : ouvre « À propos ».
struct AboutToolbarModifier: ViewModifier {
    @State private var showAbout = false

    func body(content: Content) -> some View {
        content
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showAbout = true
                    } label: {
                        AppIconView(size: 28)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("À propos de JacIPA")
                }
            }
            .sheet(isPresented: $showAbout) {
                AboutView()
            }
    }
}

extension View {
    func aboutToolbar() -> some View {
        modifier(AboutToolbarModifier())
    }
}
