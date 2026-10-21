# Supply chain baseline

The standard every matchory repository follows.

## Dependency updates

**Dependabot first.** Every ecosystem present in the repo has an entry in
`.github/dependabot.yml`. The building blocks are in
[`templates/dependabot.yml`](templates/dependabot.yml). Each entry has:

- `cooldown` with `default-days: 3` (and 3 for the semver levels). A release
  must be 3 days old before it is proposed. Security updates are not delayed.
- a `minor-and-patch` group (`update-types: [minor, patch]`): one PR per
  ecosystem.
- majors never grouped: one PR per dependency, reviewed on its own.
- a `security` group (`applies-to: security-updates`). Without it, every
  advisory is its own PR.
- `directory`/`directories` covering every manifest. `directory: /` is the
  root only; use `directories` with globs for subprojects.

**Renovate only where Dependabot cannot update something:** Puppetfile,
versions pinned in Dockerfile `ARG`s, Makefiles, scripts and workflow `env`
(annotated with `# renovate: datasource=… depName=…`), Helm values, asdf/mise.
Configs extend the central preset and add nothing Dependabot covers:

```json
{ "extends": ["github>matchory/.github//renovate/default.json5"] }
```

The preset allow-lists only those managers (`enabledManagers`), so no
dependency ever gets two PRs.

## Container images

Build with the reusable workflow, and deploy by the `digest` it outputs:

```yaml
jobs:
  image:
    uses: matchory/.github/.github/workflows/container-build.yml@<sha> # <tag>
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
    with:
      image: ghcr.io/matchory/<name>
      push: ${{ github.event_name != 'pull_request' }}
```

It sets `provenance: mode=max` and `sbom: true`, pushes a signed
build-provenance attestation to the registry, and caches layers in GHA.
Verify an image with `gh attestation verify oci://<image>@<digest> --owner matchory`.

Pin base images by tag and digest (`FROM php:8.5-alpine@sha256:…`). The
`docker` Dependabot ecosystem keeps both current.

## Workflows

- Every `uses:` is pinned to a full commit SHA, with the version in a
  comment: `uses: actions/checkout@<sha> # v7.0.1`.
- The top-level `permissions:` is `{}` or read-only. Jobs request the write
  scopes they need.
- No `${{ github.event.* }}` or other untrusted input inside `run:`. Pass it
  through `env:` instead. zizmor (org config [`zizmor.yml`](../zizmor.yml))
  must report no high-severity findings.
- Avoid `pull_request_target`. If it is unavoidable, never check out the PR
  head in it.

## Repository

- `CODEOWNERS` assigns an owner to `/.github/`, for example
  `/.github/ @matchory/infrastructure`.
- Default-branch rules (PR review, signed commits, no force push or deletion)
  come from org rulesets. Do not weaken them with repository rulesets.
