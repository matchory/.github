# .github

Org-wide defaults for matchory repositories.

- [`supply-chain/STANDARD.md`](supply-chain/STANDARD.md): the supply chain baseline every repository follows
- [`renovate/default.json5`](renovate/default.json5): central Renovate preset, limited to what Dependabot cannot update
- [`.github/workflows/container-build.yml`](.github/workflows/container-build.yml): reusable container build with provenance, SBOM and attestation
- [`.github/workflows/supply-chain-policy.yml`](.github/workflows/supply-chain-policy.yml): required PR check enforced by an org ruleset
- [`.github/workflows/supply-chain-drift.yml`](.github/workflows/supply-chain-drift.yml): daily audit, reported in the `supply-chain-drift` issue
