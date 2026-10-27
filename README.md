# JacIPA

App iPhone (SwiftUI) pour préparer des tweaks et des IPA pour LiveContainer **sans sortir le Mac**.

## Les 3 outils

1. **Deb → dylib** : ouvre un paquet `.deb` (rootless ou roothide), sort les `.dylib`, les `.bundle` et les filtres `.plist` dans `Fichiers → JacIPA → Exports/<paquet>/`. Avertit si le tweak contient des chemins `/var/jb`.
2. **Inspecter un IPA** : nom, bundle id, version, architectures, **chiffré ou déchiffré** (FairPlay / `cryptid`), liste des `.dylib` et `.framework` avec un verdict : Tweak / Dépendance / Normal.
3. **Nettoyer un IPA** : retire les tweaks choisis et leurs commandes de chargement dans le binaire principal (`LC_LOAD_DYLIB`), et écrit un IPA propre dans `Exports/`. Les tweaks peuvent aussi être **extraits** à part.

Tout se fait sur l'appareil, sans réseau. Les fichiers sont visibles dans l'app Fichiers.

## Compiler

- Ouvrir `JacIPA.xcodeproj`, choisir son équipe dans *Signing & Capabilities*, puis ▶️ sur l'iPhone.
- Cible iOS 17+. Aucune dépendance externe.

## Structure

```
JacIPA/
  JacIPAApp.swift        point d'entrée, ouverture de fichiers .deb / .ipa
  ContentView.swift      onglets
  Views/                 DebView, IPAView, ExportsView
  Core/
    ArArchive.swift      format « ar » des .deb
    TarArchive.swift     tar (ustar, GNU long names, pax)
    Decompressor.swift   gzip, xz via Compression ; zstd pas encore
    ZipReader.swift      lecture ZIP / IPA (zip64)
    ZipWriter.swift      écriture ZIP (stocké ou copie brute)
    MachO.swift          en-têtes Mach-O, cryptid, LC_LOAD_DYLIB, patch
    DebExtractor.swift   outil 1
    IPAInspector.swift   outils 2 et 3
    ExportStore.swift    dossier Exports dans Documents
    CRC32.swift, DataExtensions.swift, Errors.swift
```

## Limites connues (0.1.0)

- `.deb` compressés en **zstd** : pas encore gérés (message clair).
- IPA > 4 Go : non gérés à l'écriture.
- Le nettoyage invalide la signature : normal, LiveContainer / SideStore re-signent.
- Si un tweak retiré n'était pas le dernier dylib chargé, le binaire peut casser (ordinaux). L'app le signale.
