# .github

Org-wide defaults for matchory repositories.

- [`supply-chain/STANDARD.md`](supply-chain/STANDARD.md): the supply chain baseline every repository follows
- [`renovate/default.json5`](renovate/default.json5): central Renovate preset, limited to what Dependabot cannot update
- [`.github/workflows/container-build.yml`](.github/workflows/container-build.yml): reusable container build with provenance, SBOM and attestation
- [`zizmor.yml`](zizmor.yml): org zizmor config (`zizmor --config`), cooldown threshold matching the standard
