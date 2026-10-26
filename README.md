# .github

Org-wide defaults for matchory repositories.

- [`supply-chain/STANDARD.md`](supply-chain/STANDARD.md): the supply chain baseline every repository follows
- [`renovate/default.json5`](renovate/default.json5): central Renovate preset, limited to what Dependabot cannot update
- [`.github/workflows/container-build.yml`](.github/workflows/container-build.yml): reusable container build with provenance, SBOM and attestation
- [`.github/workflows/signed-pull-request.yml`](.github/workflows/signed-pull-request.yml) with [`actions/prepare-signed-commit`](actions/prepare-signed-commit/action.yml): pull request with a signed bot commit (e.g. regenerated build output), without exposing the app key to the build job
- [`zizmor.yml`](zizmor.yml): org zizmor config (`zizmor --config`), cooldown threshold matching the standard
