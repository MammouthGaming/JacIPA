# CI

`build-ipa.yml` doit vivre dans `.github/workflows/`. Le token GitHub de Mammouth AI n'a pas le droit `workflow`,
donc il ne peut pas écrire là. Une fois, en local :

```sh
mkdir -p .github/workflows
git mv ci/build-ipa.yml .github/workflows/build-ipa.yml
git commit -m "CI : activer le workflow Build IPA"
git push
```

Ensuite, chaque push sur `main` produit l'artefact `JacIPA-ipa` (onglet Actions → dernier run → Artifacts),
et un tag `v*` (ex. `git tag v0.2.0 && git push --tags`) publie `JacIPA.ipa` dans une Release.
