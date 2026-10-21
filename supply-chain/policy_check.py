#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml>=6", "json5>=0.9"]
# ///
"""Validate a checked-out repository against the supply chain baseline.

Runs in the org-required workflow on every pull request and exits non-zero on
a violation. Uses the same rules as audit.py, so the drift report and the PR
gate cannot disagree. Usage: ./policy_check.py [REPO_DIR]

A repo can accept a specific violation in .github/supply-chain-exceptions.yml
(owned through CODEOWNERS like the rest of .github/):

    exceptions:
      - match: "github-actions: majors grouped via actions-cache"
        reason: v4 and v6 use different cache backends and must move together

`match` is a substring of the violation message, and `reason` is required.
An exception that matches nothing is reported, so stale ones get removed.
"""
from __future__ import annotations

import sys

import yaml
from pathlib import Path

from audit import audit_dependabot, audit_workflows, codeowners_cover_github, detect_ecosystems, is_sha, minimal_perms


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    paths = [str(p.relative_to(root)) for p in root.rglob("*")
             if p.is_file() and not any(x in p.parts for x in (".git", "node_modules", "vendor"))]
    present = detect_ecosystems(paths, lambda f: (root / f).read_text(errors="replace"))

    errors: list[str] = []
    cfg = next((root / f for f in (".github/dependabot.yml", ".github/dependabot.yaml") if (root / f).exists()), None)
    if present:
        db = audit_dependabot(cfg.read_text() if cfg else None, paths, present)
        if not db["exists"]:
            errors.append(".github/dependabot.yml is missing")
        errors += [f"dependabot.yml: {p}" for p in db["problems"]]
        errors += [f"dependabot.yml: ecosystem `{e}` is present but not configured" for e in db["missing"]]
        errors += [f"dependabot.yml: {e} manifests not covered: {', '.join(d)}" for e, d in db["uncovered_dirs"].items()]

    wf_files = {p: (root / p).read_text() for p in paths
                if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")) or p.endswith(("action.yml", "action.yaml"))}
    wf = audit_workflows(wf_files)
    errors += [f"{u['file']}: `{u['uses']}` is not pinned to a full commit SHA"
               for u in wf["uses"] if u["kind"] in ("action", "reusable") and not is_sha(u["ref"])]
    errors += [f"{f}: top-level `permissions:` must be read-only (`{{}}` or `contents: read`), got {p!r}"
               for f, p in wf["top_permissions"].items() if not minimal_perms(p)]
    for b in (b for b in wf["image_builds"] if b["push"]):
        where = f"{b['file']} job {b['job']}"
        if "mode=max" not in b["provenance"]:
            errors.append(f"{where}: image build needs `provenance: mode=max`")
        if b["sbom"].lower() != "true":
            errors.append(f"{where}: image build needs `sbom: true`")
        if not (b["attest"] and b["attest"]["push_to_registry"]):
            errors.append(f"{where}: pushed image needs actions/attest-build-provenance with push-to-registry: true")

    co = next((root / f for f in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS") if (root / f).exists()), None)
    if not codeowners_cover_github(co.read_text() if co else None):
        errors.append("CODEOWNERS must assign an owner to .github/ (e.g. `/.github/ @matchory/workflows-maintainers`)")

    exc_file = root / ".github/supply-chain-exceptions.yml"
    exceptions = (yaml.safe_load(exc_file.read_text()) or {}).get("exceptions") or [] if exc_file.exists() else []
    accepted = []
    for x in exceptions:
        if not (isinstance(x, dict) and x.get("match") and str(x.get("reason") or "").strip()):
            errors.append(f"supply-chain-exceptions.yml: every exception needs `match` and `reason`: {x!r}")
            continue
        hits = [e for e in errors if x["match"] in e]
        if not hits:
            print(f"::warning::supply-chain-exceptions.yml: `{x['match']}` matches no violation; remove it")
        for e in hits:
            errors.remove(e)
            accepted.append(f"{e} (accepted: {x['reason'].strip()})")

    for e in accepted:
        print(f"::notice::{e}")
    for e in errors:
        print(f"::error::{e}")
    print(f"{len(errors)} violation(s)" if errors else "supply chain baseline: OK"
          + (f" ({len(accepted)} accepted exception(s))" if accepted else ""))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
