#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml>=6", "json5>=0.9"]
# ///
"""Read-only supply chain audit of every repository in a GitHub organization.

Writes report.md and report.json next to this file. All API responses are cached
under .cache/ (default TTL 12h) so re-runs are cheap; --refresh ignores the cache.
Nothing is ever written to GitHub: the script only issues GET requests.

Usage: ./audit.py [--org matchory] [--ttl HOURS] [--refresh] [--only REPO ...]
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import json5
import yaml

HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache"
API = "https://api.github.com"

# Central Renovate preset every Renovate config must extend (today's presets live in coding-style//renovate/).
CENTRAL_PRESET = re.compile(r"(github|local)>matchory/(\.github|renovate-config|coding-style)")
# Owners whose actions count as first-party (still expected to be SHA-pinned).
FIRST_PARTY = {"actions", "github"}

# ---------------------------------------------------------------- GitHub API


class GH:
    def __init__(self, ttl_h: float, refresh: bool):
        self.token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
        self.ttl = ttl_h * 3600
        self.refresh = refresh
        self.calls = 0
        (CACHE / "api").mkdir(parents=True, exist_ok=True)

    def get(self, path: str, accept: str = "application/vnd.github+json") -> tuple[int, object]:
        """GET with on-disk cache. Returns (status, parsed body or None)."""
        key = hashlib.sha256(f"{accept} {path}".encode()).hexdigest()
        f = CACHE / "api" / key
        if not self.refresh and f.exists() and time.time() - f.stat().st_mtime < self.ttl:
            c = json.loads(f.read_text())
            return c["status"], c["body"]
        status, body = self._fetch(path, accept)
        f.write_text(json.dumps({"path": path, "status": status, "body": body}))
        return status, body

    def paginate(self, path: str) -> list:
        out, page = [], 1
        sep = "&" if "?" in path else "?"
        while True:
            status, body = self.get(f"{path}{sep}per_page=100&page={page}")
            if status != 200:
                return out if out else None
            items = body if isinstance(body, list) else next(
                (v for v in body.values() if isinstance(v, list)), [])
            out += items
            if len(items) < 100:
                return out
            page += 1

    def _fetch(self, path: str, accept: str):
        url = path if path.startswith("http") else f"{API}/{path.lstrip('/')}"
        for attempt in range(6):
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {self.token}", "Accept": accept,
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "matchory-supply-chain-audit"})
            try:
                self.calls += 1
                with urllib.request.urlopen(req, timeout=60) as r:
                    self._throttle(r.headers)
                    raw = r.read()
                    return r.status, (json.loads(raw) if raw else None)
            except urllib.error.HTTPError as e:
                raw = e.read()
                body = None
                try:
                    body = json.loads(raw) if raw else None
                except ValueError:
                    pass
                limited = e.code == 429 or (e.code == 403 and (
                    e.headers.get("Retry-After") or e.headers.get("X-RateLimit-Remaining") == "0"))
                if limited:
                    wait = int(e.headers.get("Retry-After") or max(
                        5, int(e.headers.get("X-RateLimit-Reset", time.time() + 60)) - time.time()))
                    print(f"  rate limited, sleeping {wait}s", file=sys.stderr)
                    time.sleep(min(wait, 3600))
                    continue
                if e.code >= 500 and attempt < 5:
                    time.sleep(2 ** attempt)
                    continue
                return e.code, body
            except (urllib.error.URLError, TimeoutError):
                time.sleep(2 ** attempt)
        return 599, None

    @staticmethod
    def _throttle(h):
        remaining = int(h.get("X-RateLimit-Remaining", 1000))
        if remaining < 50:
            wait = max(0, int(h.get("X-RateLimit-Reset", 0)) - time.time()) + 5
            print(f"  {remaining} calls left, sleeping {wait:.0f}s", file=sys.stderr)
            time.sleep(wait)

    def file(self, repo: str, path: str, ref: str) -> str | None:
        status, body = self.get(f"repos/{repo}/contents/{path}?ref={ref}")
        if status != 200 or not isinstance(body, dict) or body.get("encoding") != "base64":
            return None
        return base64.b64decode(body["content"]).decode("utf-8", "replace")


# ------------------------------------------------------------ detection rules

# Dependabot package-ecosystem -> predicate on a repo path. Order matters only for display.
ECOSYSTEMS: dict[str, callable] = {
    "github-actions": lambda p: re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", p) or re.fullmatch(r"(.*/)?action\.ya?ml", p),
    "npm": lambda p: p.endswith("package.json") and "node_modules/" not in p,
    "bun": lambda p: re.search(r"(^|/)bun\.lockb?$", p),
    "composer": lambda p: p.endswith("composer.json") and "vendor/" not in p,
    # setup.py only counts when it is a packaging script (see is_setup_script)
    "pip": lambda p: re.search(r"(^|/)(requirements[^/]*\.(txt|in)|setup\.py|Pipfile|pyproject\.toml)$", p),
    "uv": lambda p: re.search(r"(^|/)uv\.lock$", p),
    "gomod": lambda p: p.endswith("go.mod"),
    "cargo": lambda p: p.endswith("Cargo.toml"),
    "bundler": lambda p: re.search(r"(^|/)Gemfile$", p),
    "maven": lambda p: p.endswith("pom.xml"),
    "gradle": lambda p: re.search(r"(^|/)build\.gradle(\.kts)?$", p),
    "nuget": lambda p: re.search(r"\.(cs|fs)proj$", p),
    "docker": lambda p: re.search(r"(^|/)(Dockerfile|Containerfile)[^/]*$|\.Dockerfile$", p),
    "docker-compose": lambda p: re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", p),
    "terraform": lambda p: p.endswith(".tf"),
    "helm": lambda p: p.endswith("Chart.yaml"),
    "devcontainers": lambda p: p.endswith("devcontainer.json"),
    "pub": lambda p: p.endswith("pubspec.yaml"),
    "swift": lambda p: p.endswith("Package.swift"),
    "mix": lambda p: p.endswith("mix.exs"),
    "pre-commit": lambda p: p.endswith(".pre-commit-config.yaml"),
}
# Ecosystems that satisfy each other (python via pip or uv, tf via terraform or opentofu).
EQUIVALENT = {"pip": {"pip", "uv"}, "uv": {"uv", "pip"}, "terraform": {"terraform", "opentofu"},
              "npm": {"npm", "bun"}, "bun": {"bun", "npm"}}

# Things Dependabot cannot update: the legitimate Renovate scope.
DEPENDABOT_GAPS: dict[str, callable] = {
    "puppet (Puppetfile)": lambda p: re.search(r"(^|/)Puppetfile$", p),
    "asdf/mise (.tool-versions, mise.toml)": lambda p: re.search(r"(^|/)(\.tool-versions|\.?mise\.toml)$", p),
    "ansible-galaxy": lambda p: re.search(r"(^|/)requirements\.ya?ml$", p) and "roles" in p or p.endswith("galaxy.yml"),
    "kustomize": lambda p: p.endswith("kustomization.yaml"),
    "helm values / helmfile": lambda p: re.search(r"(^|/)(helmfile\.ya?ml|values[^/]*\.ya?ml)$", p),
    "Makefile/scripts (custom regex)": lambda p: re.search(r"(^|/)(Makefile|[^/]+\.mk)$", p),
    "nix": lambda p: p.endswith("flake.nix"),
    "jsonnet-bundler": lambda p: p.endswith("jsonnetfile.json"),
}
# Dependabot ecosystem -> Renovate managers that would update the same files.
RENOVATE_MANAGERS = {
    "npm": {"npm"}, "bun": {"bun", "npm"}, "composer": {"composer"},
    "pip": {"pip_requirements", "pip_setup", "pipenv", "poetry", "pep621", "setup-cfg"},
    "uv": {"pep621"}, "gomod": {"gomod"}, "cargo": {"cargo"}, "bundler": {"bundler"},
    "maven": {"maven"}, "gradle": {"gradle"}, "nuget": {"nuget"}, "docker": {"dockerfile"},
    "docker-compose": {"docker-compose"}, "github-actions": {"github-actions"},
    "terraform": {"terraform"}, "opentofu": {"terraform"}, "helm": {"helmv3"},
    "devcontainers": {"devcontainer"}, "pub": {"pub"}, "swift": {"swift"}, "mix": {"mix"},
    "pre-commit": {"pre-commit"},
}
RENOVATE_FILES = ["renovate.json", "renovate.json5", ".github/renovate.json", ".github/renovate.json5",
                  ".gitlab/renovate.json", ".renovaterc", ".renovaterc.json", ".renovaterc.json5"]
IMAGE_BUILD_ACTIONS = {"docker/build-push-action", "depot/build-push-action", "redhat-actions/buildah-build",
                       "docker/bake-action", "int128/kaniko-action", "ko-build/setup-ko"}
PUBLISH_PATTERNS = re.compile(
    r"npm publish|pnpm publish|yarn (npm )?publish|twine upload|uv publish|poetry publish|"
    r"goreleaser|gh release create|mvn deploy|gradle\w* publish|cargo publish|helm push")
PUBLISH_ACTIONS = {"pypa/gh-action-pypi-publish", "softprops/action-gh-release", "goreleaser/goreleaser-action",
                   "JS-DevTools/npm-publish", "ncipollo/release-action", "changesets/action"}

OK, BAD, NA = "✅", "❌", "n.a."


def is_setup_script(text: str) -> bool:
    """A setup.py is a pip manifest only if it packages something; a module that happens to be called setup.py is not."""
    return bool(re.search(r"^\s*(from|import)\s+(setuptools|distutils)", text, re.M))


def detect_ecosystems(paths: list[str], read) -> dict[str, set[str]]:
    """Map each Dependabot ecosystem present to the directories holding its manifests."""
    present: dict[str, set[str]] = {}
    for p in paths:
        for eco, pred in ECOSYSTEMS.items():
            if not pred(p):
                continue
            if eco == "pip" and p.endswith("setup.py") and not is_setup_script(read(p) or ""):
                continue
            parent = str(Path(p).parent)
            present.setdefault(eco, set()).add("/" if parent == "." else f"/{parent}")
    return present


def mark(v):
    return NA if v is None else (OK if v else BAD)


def parse_uses(u: str):
    """('owner/repo', 'ref', kind) for a `uses:` value; kind local|docker|action|reusable."""
    if u.startswith("./"):
        return u, None, "local"
    if u.startswith("docker://"):
        return u, ("sha256" if "@sha256:" in u else None), "docker"
    name, _, ref = u.partition("@")
    parts = name.split("/")
    kind = "reusable" if "/.github/workflows/" in name else "action"
    return "/".join(parts[:2]), ref, kind


def is_sha(ref: str | None) -> bool:
    return bool(ref) and bool(re.fullmatch(r"[0-9a-f]{40}", ref))


# ------------------------------------------------------------- per-repo audit


def audit_dependabot(text: str | None, paths: list[str], present: dict[str, set[str]]):
    r = {"exists": text is not None, "valid": None, "configured": [], "missing": [], "uncovered_dirs": {},
         "cooldown_ok": None, "groups_ok": None, "majors_separate": None, "problems": []}
    if text is None:
        r["missing"] = sorted(present)
        return r
    try:
        cfg = yaml.safe_load(text) or {}
        updates = cfg.get("updates") or []
    except yaml.YAMLError as e:
        r["valid"] = False
        r["problems"].append(f"YAML error: {e}")
        return r
    r["valid"] = True
    meg = cfg.get("multi-ecosystem-groups") or {}
    configured: dict[str, list[str]] = {}
    excluded: dict[str, list[str]] = {}
    cool, grp, maj = [], [], []
    for u in updates:
        eco = (u.get("package-ecosystem") or "").strip()
        if not eco:
            r["valid"] = False
            r["problems"].append("empty package-ecosystem (unedited scaffold: no updates ever run)")
            continue
        dirs = u.get("directories") or ([u["directory"]] if u.get("directory") else [])
        configured.setdefault(eco, []).extend(dirs)
        excluded.setdefault(eco, []).extend(u.get("exclude-paths") or [])
        # cooldown: explicit 3 days on every level that is set
        c = u.get("cooldown") or {}
        days = [c.get(k) for k in ("default-days", "semver-major-days", "semver-minor-days", "semver-patch-days") if k in c]
        ok_c = c.get("default-days") == 3 and all(d == 3 for d in days)
        cool.append(ok_c)
        if not ok_c:
            r["problems"].append(f"{eco}: cooldown {c or 'missing'} (want default-days: 3)")
        # groups: minor+patch grouped, majors excluded from every group
        groups = dict(u.get("groups") or {})
        if u.get("multi-ecosystem-group") in meg:
            groups[f"meg:{u['multi-ecosystem-group']}"] = {
                "update-types": u.get("update-types") or meg[u["multi-ecosystem-group"]].get("update-types")}
        version_groups = {k: g for k, g in groups.items() if (g or {}).get("applies-to", "version-updates") == "version-updates"}
        has_mp = any({"minor", "patch"} <= set((g or {}).get("update-types") or []) for g in version_groups.values())
        majors_grouped = [k for k, g in version_groups.items()
                          if not (g or {}).get("update-types") or "major" in (g or {}).get("update-types")]
        grp.append(has_mp)
        maj.append(not majors_grouped)
        if not has_mp:
            r["problems"].append(f"{eco}: no group with update-types [minor, patch]")
        if majors_grouped:
            r["problems"].append(f"{eco}: majors grouped via {', '.join(majors_grouped)} (no update-types filter or includes major)")
    r["configured"] = sorted(configured)
    r["cooldown_ok"] = all(cool) if cool else None
    r["groups_ok"] = all(grp) if grp else None
    r["majors_separate"] = all(maj) if maj else None
    r["missing"] = sorted(e for e in present if not (EQUIVALENT.get(e, {e}) & set(configured)))
    # directory coverage: every manifest dir must match one configured dir/glob
    for eco, dirs_present in present.items():
        conf = [d for e in EQUIVALENT.get(eco, {eco}) for d in configured.get(e, [])]
        if not conf or eco == "github-actions":
            continue
        # a root npm entry updates every pnpm workspace member through the root lockfile
        if eco == "npm" and "pnpm-workspace.yaml" in paths and "/" in conf:
            continue
        pats = ["/" + d.strip("/") if d.strip("/") else "/" for d in conf]
        excl = [x.strip("/") for e in EQUIVALENT.get(eco, {eco}) for x in excluded.get(e, [])]
        unc = sorted(d for d in dirs_present
                     if not any(fnmatch.fnmatch(d, p) or p == "/**" for p in pats)
                     and not any(fnmatch.fnmatch(d.strip("/"), x) or fnmatch.fnmatch(d.strip("/") + "/", x)
                                 or d.strip("/").startswith(x.rstrip("*").rstrip("/") + "/") for x in excl))
        if unc:
            r["uncovered_dirs"][eco] = unc
    return r


def audit_renovate(gh: GH, repo: str, ref: str, paths: set[str], dependabot_ecos: list[str], present: list[str]):
    f = next((p for p in RENOVATE_FILES if p in paths), None)
    src = f
    cfg = None
    if f:
        try:
            cfg = json5.loads(gh.file(repo, f, ref) or "{}")
        except ValueError as e:
            return {"file": f, "error": str(e)}
    elif "package.json" in paths:
        try:
            pkg = json.loads(gh.file(repo, "package.json", ref) or "{}")
            if "renovate" in pkg:
                cfg, src = pkg["renovate"], "package.json#renovate"
        except ValueError:
            pass
    if cfg is None:
        return None
    extends = cfg.get("extends") or []
    enabled = cfg.get("enabledManagers")
    disabled = {m for rule in cfg.get("packageRules") or [] if rule.get("enabled") is False
                for m in rule.get("matchManagers") or []}
    disabled |= {k for k, v in cfg.items() if isinstance(v, dict) and v.get("enabled") is False}
    active = (lambda m: m in enabled) if enabled is not None else (lambda m: m not in disabled)
    overlap = sorted(e for e in dependabot_ecos if any(active(m) for m in RENOVATE_MANAGERS.get(e, set())))
    # ecosystems in the repo that Dependabot supports but Renovate is (also) allowed to update
    beyond = sorted(e for e in present if any(active(m) for m in RENOVATE_MANAGERS.get(e, set())))
    grouped = any(rule.get("groupName") for rule in cfg.get("packageRules") or []) or any(
        re.match(r"group:", x) for x in extends)
    r = {"file": src, "extends": extends,
         "central_preset": any(CENTRAL_PRESET.search(x) for x in extends),
         "minimum_release_age": cfg.get("minimumReleaseAge"),
         "min_age_ok": cfg.get("minimumReleaseAge") == "3 days",
         "separate_major_minor": cfg.get("separateMajorMinor", True) is not False,
         "grouped": grouped, "enabled_managers": enabled,
         "custom_managers": len(cfg.get("customManagers") or cfg.get("regexManagers") or []),
         "overlap_with_dependabot": overlap, "dependabot_capable_in_renovate": beyond,
         # with no enabledManagers, Renovate runs every manager it supports
         "unrestricted": enabled is None}
    r["ok"] = r["central_preset"] and r["min_age_ok"] and r["separate_major_minor"] and r["grouped"] and not beyond
    return r


def audit_workflows(files: dict[str, str]):
    """Parse workflow/action YAML. Returns workflow-hardening and container-build facts."""
    wf = {"count": 0, "top_permissions": {}, "uses": [], "pull_request_target": [], "reusable_called": [],
          "image_builds": [], "publishes": set(), "codeql": False, "parse_errors": []}
    for path, text in files.items():
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            wf["parse_errors"].append(f"{path}: {e.__class__.__name__}")
            continue
        if not isinstance(doc, dict):
            continue
        is_workflow = path.startswith(".github/workflows/")
        if is_workflow:
            wf["count"] += 1
            # PyYAML turns the bare key `on` into True
            on = doc.get("on", doc.get(True)) or {}
            triggers = [on] if isinstance(on, str) else (list(on) if isinstance(on, (dict, list)) else [])
            if "pull_request_target" in triggers:
                wf["pull_request_target"].append(path)
            wf["top_permissions"][path] = doc.get("permissions", "MISSING")
        jobs = doc.get("jobs") or {}
        steps_by_job = {jid: (j or {}).get("steps") or [] for jid, j in jobs.items()} if is_workflow \
            else {"(action)": ((doc.get("runs") or {}).get("steps") or [])}
        for jid, job in (jobs.items() if is_workflow else []):
            if isinstance(job, dict) and job.get("uses"):
                name, ref, kind = parse_uses(job["uses"])
                wf["uses"].append({"file": path, "uses": job["uses"], "name": name, "ref": ref, "kind": kind})
                wf["reusable_called"].append(job["uses"])
        for jid, steps in steps_by_job.items():
            job = jobs.get(jid) if is_workflow else {}
            job = job if isinstance(job, dict) else {}
            perms = job.get("permissions", doc.get("permissions") if is_workflow else None)
            attest = None
            builds = []
            for s in steps if isinstance(steps, list) else []:
                if not isinstance(s, dict):
                    continue
                run = str(s.get("run") or "")
                if PUBLISH_PATTERNS.search(run):
                    wf["publishes"].add("package/release")
                if s.get("uses"):
                    name, ref, kind = parse_uses(str(s["uses"]))
                    wf["uses"].append({"file": path, "uses": s["uses"], "name": name, "ref": ref, "kind": kind})
                    w = s.get("with") or {}
                    if name in PUBLISH_ACTIONS:
                        wf["publishes"].add("package/release")
                    if name == "github/codeql-action":
                        wf["codeql"] = True
                    if name in IMAGE_BUILD_ACTIONS:
                        builds.append({"tool": name, # push is often an expression (`${{ github.event_name != 'pull_request' }}`): anything but false counts
                                       "push": str(w.get("push", "")).lower() not in ("", "false") or "push=true" in str(w.get("outputs", "")),
                                       "provenance": str(w.get("provenance", "")), "sbom": str(w.get("sbom", "")),
                                       "cache": " ".join(str(w.get(k, "")) for k in ("cache-from", "cache-to"))})
                    if name in ("actions/attest-build-provenance", "actions/attest"):
                        attest = {"push_to_registry": str(w.get("push-to-registry", "")).lower() == "true"}
                elif re.search(r"\b(docker|podman|buildah)( buildx)? (build|push)\b", run):
                    builds.append({"tool": "cli", "push": bool(re.search(r"docker push|--push\b|podman push", run)),
                                   "provenance": (re.search(r"--provenance[= ](\S+)", run) or [None, ""])[1],
                                   "sbom": (re.search(r"--sbom[= ](\S+)", run) or [None, ""])[1],
                                   "cache": " ".join(re.findall(r"--cache-(?:from|to)[= ](\S+)", run))})
            for b in builds:
                p = perms if isinstance(perms, dict) else {}
                b.update(file=path, job=jid, attest=attest,
                         id_token=p.get("id-token") == "write" or perms == "write-all",
                         attestations=p.get("attestations") == "write" or perms == "write-all")
                if b["push"]:
                    wf["publishes"].add("image")
                wf["image_builds"].append(b)
    wf["publishes"] = sorted(wf["publishes"])
    return wf


def minimal_perms(p) -> bool:
    """Top-level permissions grant nothing beyond read. MISSING means the default token applies."""
    return p == "read-all" or isinstance(p, dict) and all(v in ("read", "none") for v in p.values())


def audit_dockerfiles(files: dict[str, str]):
    total, pinned, unpinned = 0, 0, []
    for path, text in files.items():
        stages = set()
        for line in text.splitlines():
            m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
            if not m:
                continue
            img = m.group(1)
            if m.group(2):
                stages.add(m.group(2).lower())
            if img.lower() in stages or img == "scratch":
                continue
            total += 1
            if "@sha256:" in img:
                pinned += 1
            else:
                unpinned.append(f"{path}: {img}")
    return {"from_total": total, "from_pinned": pinned, "unpinned": unpinned}


def codeowners_cover_github(text: str | None) -> bool | None:
    if text is None:
        return None
    probe = ".github/workflows/x.yml"
    covered = False
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        pat, *owners = line.split()
        anchored = pat.startswith("/")
        p = pat.lstrip("/")
        if p.endswith("/"):
            p += "**"
        cands = [p] if anchored or "/" in p.rstrip("*").rstrip("/") else [p, f"**/{p}"]
        hit = any(fnmatch.fnmatch(probe, c) or fnmatch.fnmatch(probe, c + "/**") for c in cands) or p in ("*", "**")
        if hit:
            covered = bool(owners)  # last match wins; ownerless entry removes ownership
    return covered


def run_zizmor(repo_dir: Path):
    if not shutil.which("zizmor") or not repo_dir.exists():
        return None
    p = subprocess.run(["zizmor", "--format", "json", "--offline", "--no-progress", str(repo_dir)],
                       capture_output=True, text=True)
    try:
        findings = json.loads(p.stdout)
    except ValueError:
        return {"error": (p.stderr or "")[-300:]}
    sev, rules = {}, {}
    for f in findings:
        s = (f.get("determinations") or {}).get("severity", "Unknown")
        sev[s] = sev.get(s, 0) + 1
        rules[f.get("ident")] = rules.get(f.get("ident"), 0) + 1
    return {"total": len(findings), "by_severity": sev, "by_rule": rules}


def audit_repo(gh: GH, org: str, meta: dict) -> dict:
    repo = meta["full_name"]
    ref = meta["default_branch"]
    r = {"name": meta["name"], "visibility": meta["visibility"], "default_branch": ref,
         "fork": meta["fork"], "pushed_at": meta["pushed_at"], "language": meta.get("language")}
    status, tree = gh.get(f"repos/{repo}/git/trees/{ref}?recursive=1")
    if status != 200:
        r["error"] = f"tree: HTTP {status}"
        return r
    paths = [t["path"] for t in tree.get("tree", []) if t["type"] == "blob"]
    r["tree_truncated"] = tree.get("truncated", False)
    pset = set(paths)

    present = detect_ecosystems(paths, lambda f: gh.file(repo, f, ref))
    r["ecosystems_present"] = sorted(present)
    r["dependabot_gaps_present"] = sorted(g for g, pred in DEPENDABOT_GAPS.items() if any(pred(p) for p in paths))

    db_path = next((p for p in (".github/dependabot.yml", ".github/dependabot.yaml") if p in pset), None)
    r["dependabot"] = audit_dependabot(gh.file(repo, db_path, ref) if db_path else None, paths, present)
    r["renovate"] = audit_renovate(gh, repo, ref, pset, r["dependabot"]["configured"], r["ecosystems_present"])

    # workflows + composite actions, mirrored to disk for zizmor
    mirror = CACHE / "repos" / meta["name"]
    shutil.rmtree(mirror, ignore_errors=True)
    wf_files = {}
    for p in paths:
        if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", p) or re.fullmatch(r"(.*/)?action\.ya?ml", p):
            text = gh.file(repo, p, ref)
            if text is not None:
                wf_files[p] = text
                (mirror / p).parent.mkdir(parents=True, exist_ok=True)
                (mirror / p).write_text(text)
    wf = audit_workflows(wf_files)
    if any(re.fullmatch(r"action\.ya?ml", p) for p in paths):
        wf["publishes"] = sorted(set(wf["publishes"]) | {"action"})
    r["workflows"] = wf
    r["zizmor"] = run_zizmor(mirror) if wf_files else None
    docker_files = {p: gh.file(repo, p, ref) or "" for p in paths if ECOSYSTEMS["docker"](p)}
    r["dockerfiles"] = audit_dockerfiles(docker_files)

    # CODEOWNERS
    co_path = next((p for p in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS") if p in pset), None)
    r["codeowners"] = {"path": co_path,
                       "covers_github": codeowners_cover_github(gh.file(repo, co_path, ref) if co_path else None)}
    if co_path:
        s, b = gh.get(f"repos/{repo}/codeowners/errors")
        r["codeowners"]["errors"] = len((b or {}).get("errors", [])) if s == 200 else None

    # security settings
    sa = meta.get("security_and_analysis") or {}
    st = lambda k: (sa.get(k) or {}).get("status")  # noqa: E731
    s_alerts, _ = gh.get(f"repos/{repo}/vulnerability-alerts")
    s_fix, b_fix = gh.get(f"repos/{repo}/automated-security-fixes")
    s_cs, b_cs = gh.get(f"repos/{repo}/code-scanning/default-setup")
    r["security"] = {
        "dependabot_alerts": s_alerts == 204,
        "security_updates": bool((b_fix or {}).get("enabled")) if s_fix == 200 else False,
        "secret_scanning": st("secret_scanning") == "enabled",
        "push_protection": st("secret_scanning_push_protection") == "enabled",
        "code_scanning_default": (b_cs or {}).get("state") == "configured" if s_cs == 200 else None,
    }
    # dependency graph: implied for public repos and by enabled alerts; else probe SBOM export
    if meta["visibility"] == "public" or s_alerts == 204:
        r["security"]["dependency_graph"] = True
    else:
        s_sbom, _ = gh.get(f"repos/{repo}/dependency-graph/sbom")
        r["security"]["dependency_graph"] = s_sbom == 200
    r["security"]["code_scanning"] = bool(r["security"]["code_scanning_default"]) or wf["codeql"]

    # effective rules on the default branch (repo + org rulesets) and classic protection
    s_rules, rules = gh.get(f"repos/{repo}/rules/branches/{ref}")
    rules = rules if s_rules == 200 and isinstance(rules, list) else []
    types = {x["type"]: x.get("parameters") or {} for x in rules}
    s_bp, bp = gh.get(f"repos/{repo}/branches/{ref}/protection")
    bp = bp if s_bp == 200 else {}
    pr = types.get("pull_request", {})
    reviews = (pr.get("required_approving_review_count") or 0) >= 1 or bool(
        (bp.get("required_pull_request_reviews") or {}).get("required_approving_review_count"))
    r["branch"] = {
        "reviews": reviews,
        "code_owner_review": bool(pr.get("require_code_owner_review")) or bool(
            (bp.get("required_pull_request_reviews") or {}).get("require_code_owner_reviews")),
        "status_checks": "required_status_checks" in types or bool(bp.get("required_status_checks")),
        "no_force_push": "non_fast_forward" in types or (bool(bp) and not (bp.get("allow_force_pushes") or {}).get("enabled")),
        "signed_commits": "required_signatures" in types or bool((bp.get("required_signatures") or {}).get("enabled")),
        "required_workflows": [w.get("path") for x in rules if x["type"] == "workflows"
                               for w in (x.get("parameters") or {}).get("workflows", [])],
        "rule_types": sorted(types), "classic_protection": bool(bp),
    }
    rs = gh.paginate(f"repos/{repo}/rulesets?includes_parents=true") or []
    r["tags_protected"] = any(x.get("target") == "tag" and x.get("enforcement") == "active" for x in rs)
    s_im, b_im = gh.get(f"repos/{repo}/immutable-releases")
    r["immutable_releases"] = bool((b_im or {}).get("enabled")) if s_im == 200 else None
    s_ap, b_ap = gh.get(f"repos/{repo}/actions/permissions")
    r["actions_policy"] = b_ap if s_ap == 200 else None
    s_wp, b_wp = gh.get(f"repos/{repo}/actions/permissions/workflow")
    r["default_token"] = (b_wp or {}).get("default_workflow_permissions") if s_wp == 200 else None
    return r


# ------------------------------------------------------------------ criteria


def criteria(r: dict) -> dict:
    """Map a repo result to {criterion: True/False/None(n.a.)}."""
    db, wf, sec, br = r["dependabot"], r["workflows"], r["security"], r["branch"]
    has_eco = bool(r["ecosystems_present"])
    builds = wf["image_builds"]
    pushed = [b for b in builds if b["push"]]
    ext = [u for u in wf["uses"] if u["kind"] in ("action", "reusable")]
    third = [u for u in ext if u["name"].split("/")[0] not in FIRST_PARTY | {"matchory"}]
    zz = r.get("zizmor") or {}
    zz_high = (zz.get("by_severity") or {}).get("High", 0) if "by_severity" in zz else None
    reno = r["renovate"]
    return {
        # dependency updates
        "dependabot.yml valid": (db["exists"] and db["valid"]) if has_eco else None,
        "all ecosystems covered": (not db["missing"]) if has_eco else None,
        "all manifest dirs covered": (not db["uncovered_dirs"]) if db["configured"] else None,
        "cooldown 3d": db["cooldown_ok"],
        "minor+patch grouped": db["groups_ok"],
        "majors separate": db["majors_separate"],
        "renovate scoped to gaps": reno["ok"] if reno and "ok" in reno else (False if reno else None),
        "dependabot alerts": sec["dependabot_alerts"],
        "security updates": sec["security_updates"],
        "dependency graph": sec["dependency_graph"],
        # container builds
        "provenance mode=max": all("mode=max" in b["provenance"] for b in pushed) if pushed else None,
        "sbom": all(b["sbom"].lower() == "true" for b in pushed) if pushed else None,
        "attested + perms": all(b["attest"] and b["attest"]["push_to_registry"] and b["id_token"] and b["attestations"]
                                for b in pushed) if pushed else None,
        "build cache": all(re.search(r"type=(gha|registry)", b["cache"]) for b in builds) if builds else None,
        "base images by digest": (r["dockerfiles"]["from_pinned"] == r["dockerfiles"]["from_total"])
        if r["dockerfiles"]["from_total"] else None,
        "central build workflow": any("matchory/" in u for u in wf["reusable_called"]) if builds or any(
            "matchory/" in u for u in wf["reusable_called"]) else None,
        # workflow hardening
        "all actions SHA-pinned": all(is_sha(u["ref"]) for u in ext) if ext else None,
        "3rd-party SHA-pinned": all(is_sha(u["ref"]) for u in third) if third else None,
        "top-level permissions minimal": all(minimal_perms(p) for p in wf["top_permissions"].values())
        if wf["top_permissions"] else None,
        "no pull_request_target": (not wf["pull_request_target"]) if wf["count"] else None,
        "zizmor: no high": (zz_high == 0) if zz_high is not None else None,
        # settings
        "PR reviews": br["reviews"],
        "status checks": br["status_checks"],
        "no force push": br["no_force_push"],
        "signed commits": br["signed_commits"],
        "CODEOWNERS covers .github": bool(r["codeowners"]["covers_github"]),
        "secret scanning": sec["secret_scanning"],
        "push protection": sec["push_protection"],
        "code scanning": sec["code_scanning"],
        "tag protection": r["tags_protected"],
        "immutable releases": r["immutable_releases"],
    }


SECTIONS = {
    "Dependency updates": ["dependabot.yml valid", "all ecosystems covered", "all manifest dirs covered", "cooldown 3d",
                           "minor+patch grouped", "majors separate", "renovate scoped to gaps", "dependabot alerts",
                           "security updates", "dependency graph"],
    "Container builds": ["provenance mode=max", "sbom", "attested + perms", "build cache", "base images by digest",
                         "central build workflow"],
    "Workflow hardening": ["all actions SHA-pinned", "3rd-party SHA-pinned", "top-level permissions minimal",
                           "no pull_request_target", "zizmor: no high"],
    "Repo settings": ["PR reviews", "status checks", "no force push", "signed commits", "CODEOWNERS covers .github",
                      "secret scanning", "push protection", "code scanning", "tag protection", "immutable releases"],
}


def risk(r: dict) -> tuple:
    pub = r["workflows"]["publishes"]
    tier = 0 if "image" in pub else 1 if pub else 2
    fails = sum(1 for v in r["criteria"].values() if v is False)
    return (tier, 0 if r["visibility"] == "public" else 1, -fails, r["name"])


# ------------------------------------------------------------------ org level


def audit_org(gh: GH, org: str, enterprise: str | None) -> dict:
    o = {}
    _, meta = gh.get(f"orgs/{org}")
    o["plan"] = (meta.get("plan") or {}).get("name")
    for k in ("dependabot_alerts_enabled_for_new_repositories", "dependabot_security_updates_enabled_for_new_repositories",
              "dependency_graph_enabled_for_new_repositories", "secret_scanning_enabled_for_new_repositories",
              "secret_scanning_push_protection_enabled_for_new_repositories", "two_factor_requirement_enabled",
              "members_can_create_public_repositories"):
        o[k] = meta.get(k)
    for key, path in (("actions_permissions", "actions/permissions"),
                      ("workflow_permissions", "actions/permissions/workflow"),
                      ("selected_actions", "actions/permissions/selected-actions"),
                      ("immutable_releases", "settings/immutable-releases"),
                      ("security_config_defaults", "code-security/configurations/defaults")):
        s, b = gh.get(f"orgs/{org}/{path}")
        o[key] = b if s == 200 else f"HTTP {s}: {(b or {}).get('message', '') if isinstance(b, dict) else ''}"
    s, cfgs = gh.get(f"orgs/{org}/code-security/configurations")
    o["security_configs"] = [{k: c.get(k) for k in ("id", "name", "target_type", "dependency_graph", "dependabot_alerts",
                              "dependabot_security_updates", "secret_scanning", "secret_scanning_push_protection",
                              "code_scanning_default_setup")} for c in (cfgs or [])] if s == 200 else f"HTTP {s}"
    rulesets = []
    for rs in gh.paginate(f"orgs/{org}/rulesets") or []:
        s, full = gh.get(f"orgs/{org}/rulesets/{rs['id']}")
        if s == 200:
            rulesets.append({"name": full["name"], "target": full["target"], "enforcement": full["enforcement"],
                             "conditions": full.get("conditions"),
                             "rules": [{"type": x["type"], **({"parameters": x["parameters"]} if x.get("parameters") else {})}
                                       for x in full.get("rules", [])]})
    o["rulesets"] = rulesets
    s, inst = gh.get(f"orgs/{org}/installations?per_page=100")
    o["apps"] = sorted(f"{i['app_slug']} ({i['repository_selection']})" for i in (inst or {}).get("installations", []))
    o["enterprise"] = audit_enterprise(gh, enterprise)
    return o


def audit_enterprise(gh: GH, slug: str | None) -> dict | str:
    if not slug:
        return "not checked: no enterprise slug (--enterprise)"
    e = {"slug": slug}
    for key, path in (("actions_permissions", "actions/permissions"),
                      ("selected_actions", "actions/permissions/selected-actions"),
                      ("workflow_permissions", "actions/permissions/workflow"),
                      ("rulesets", "rulesets")):
        s, b = gh.get(f"enterprises/{slug}/{path}")
        e[key] = b if s == 200 else f"HTTP {s}: {(b or {}).get('message', '') if isinstance(b, dict) else ''}"
    s, cfgs = gh.get(f"enterprises/{slug}/code-security/configurations")
    e["security_configs"] = [{k: c.get(k) for k in ("id", "name", "enforcement", "dependency_graph", "dependabot_alerts",
                              "dependabot_security_updates", "secret_scanning", "secret_scanning_push_protection",
                              "code_scanning_default_setup")} for c in (cfgs or [])] if s == 200 else (
        f"HTTP {s}: token needs admin:enterprise")
    return e


# ------------------------------------------------------------------ reporting


def write_reports(org: str, org_res: dict, repos: list[dict], archived: list[dict], skipped: list[dict], gh: GH):
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    (HERE / "report.json").write_text(json.dumps(
        {"generated": now, "org": org, "org_settings": org_res, "repos": repos, "skipped": skipped, "archived": archived},
        indent=1, default=sorted, ensure_ascii=False))
    L = [f"# Supply chain audit: `{org}`", "",
         f"Generated {now}. {len(repos)} active repositories, {len(archived)} archived (listed at the end, not audited). "
         f"{gh.calls} uncached API calls this run.", "",
         "Read-only. ✅ compliant, ❌ gap, n.a. = criterion does not apply (e.g. no image build, no workflows). "
         "Sorted by risk: repos that push images first, then other publishers (packages, releases, actions), "
         "public before private, most gaps first.", "", "## Compliance by criterion", "",
         "| Area | Criterion | Compliant | Applicable | Rate |", "|---|---|--:|--:|--:|"]
    for sec, keys in SECTIONS.items():
        for k in keys:
            vals = [r["criteria"][k] for r in repos if r["criteria"][k] is not None]
            ok = sum(1 for v in vals if v)
            L.append(f"| {sec} | {k} | {ok} | {len(vals)} | {(100 * ok / len(vals)):.0f}% |" if vals
                     else f"| {sec} | {k} | 0 | 0 | n.a. |")
    L += ["", "## Organization settings", "", "```json", json.dumps(
        {k: v for k, v in org_res.items() if k != "rulesets"}, indent=1, ensure_ascii=False), "```", "",
          "### Org rulesets", "", "| Ruleset | Target | Enforcement | Rules |", "|---|---|---|---|"]
    for rs in org_res["rulesets"]:
        L.append(f"| {rs['name']} | {rs['target']} | {rs['enforcement']} | {', '.join(x['type'] for x in rs['rules'])} |")
    for sec, keys in SECTIONS.items():
        L += ["", f"## {sec}", "", "| Repo | Vis | Publishes | " + " | ".join(keys) + " |",
              "|---|---|---|" + "---|" * len(keys)]
        for r in repos:
            L.append(f"| {r['name']} | {r['visibility'][:4]} | {', '.join(r['workflows']['publishes']) or '–'} | "
                     + " | ".join(mark(r["criteria"][k]) for k in keys) + " |")
    L += ["", "## Findings per repository", ""]
    for r in repos:
        db, wf = r["dependabot"], r["workflows"]
        notes = []
        if db["missing"]:
            notes.append(f"Ecosystems present but not in dependabot.yml: {', '.join(db['missing'])}")
        for eco, dirs in db["uncovered_dirs"].items():
            notes.append(f"{eco} manifests outside configured directories: {', '.join(dirs[:6])}{' …' if len(dirs) > 6 else ''}")
        notes += db["problems"][:8]
        if r["dependabot_gaps_present"]:
            notes.append(f"Dependabot blind spots present (Renovate scope): {', '.join(r['dependabot_gaps_present'])}")
        if r["renovate"]:
            rv = r["renovate"]
            if "error" in rv:
                notes.append(f"Renovate config {rv['file']} unparsable: {rv['error']}")
            else:
                notes.append(f"Renovate ({rv['file']}): extends {rv['extends'] or '[]'}, minimumReleaseAge "
                             f"{rv['minimum_release_age']!r}, enabledManagers {rv['enabled_managers'] or 'ALL'}, "
                             f"{rv['custom_managers']} custom managers"
                             + (f"; **overlaps Dependabot on {', '.join(rv['overlap_with_dependabot'])}**" if rv['overlap_with_dependabot'] else "")
                             + (f"; handles Dependabot-capable {', '.join(rv['dependabot_capable_in_renovate'])}" if rv['dependabot_capable_in_renovate'] else ""))
        for b in wf["image_builds"]:
            notes.append(f"Image build `{b['file']}` job `{b['job']}` via {b['tool']}: push={b['push']}, "
                         f"provenance={b['provenance'] or 'default'}, sbom={b['sbom'] or 'default'}, "
                         f"cache={b['cache'].strip() or 'none'}, attest={'yes' if b['attest'] else 'no'}, "
                         f"id-token:write={b['id_token']}, attestations:write={b['attestations']}")
        unpinned = sorted({u["uses"] for u in wf["uses"] if u["kind"] in ("action", "reusable") and not is_sha(u["ref"])})
        if unpinned:
            notes.append(f"Unpinned uses ({len(unpinned)}): {', '.join(f'`{u}`' for u in unpinned[:10])}{' …' if len(unpinned) > 10 else ''}")
        bad_perms = [f for f, p in wf["top_permissions"].items() if not minimal_perms(p)]
        if bad_perms:
            notes.append(f"Workflows without minimal top-level permissions: {', '.join(bad_perms[:8])}")
        if wf["pull_request_target"]:
            notes.append(f"pull_request_target: {', '.join(wf['pull_request_target'])}")
        if r.get("zizmor") and r["zizmor"].get("by_rule"):
            notes.append("zizmor: " + ", ".join(f"{k}×{v}" for k, v in sorted(r["zizmor"]["by_rule"].items())))
        if r["dockerfiles"]["unpinned"]:
            u = r["dockerfiles"]["unpinned"]
            notes.append(f"Base images not pinned by digest ({len(u)}): {'; '.join(u[:5])}{' …' if len(u) > 5 else ''}")
        if r["branch"]["required_workflows"]:
            notes.append(f"Required workflows: {r['branch']['required_workflows']}")
        if r.get("tree_truncated"):
            notes.append("Git tree truncated by the API: ecosystem detection may be incomplete")
        if wf["parse_errors"]:
            notes.append(f"Unparsable workflow YAML: {', '.join(wf['parse_errors'])}")
        if notes:
            L += [f"### {r['name']}", ""] + [f"- {n}" for n in notes] + [""]
    if skipped:
        L += ["## Skipped", ""] + [f"- {x['name']}: {x['reason']}" for x in skipped] + [""]
    L += ["## Archived repositories (not audited)", "",
          ", ".join(f"{a['name']} ({a['visibility'][:4]})" for a in archived), ""]
    (HERE / "report.md").write_text("\n".join(L))


def write_drift(previous: Path, repos: list[dict]) -> int:
    """Compare with an earlier report.json; write drift.md. Returns the number of regressions."""
    prev = {r["name"]: r["criteria"] for r in json.loads(previous.read_text())["repos"]} if previous.exists() else {}
    regressions, fixed, new = [], 0, []
    for r in repos:
        before = prev.get(r["name"])
        if before is None:
            if prev:
                new.append(r["name"])
            continue
        for k, v in r["criteria"].items():
            if before.get(k) is True and v is False:
                regressions.append((r["name"], k))
            elif before.get(k) is False and v is True:
                fixed += 1
    L = ["<!-- supply-chain-drift -->", "# Supply chain drift", ""]
    if not prev:
        L.append("First run: no earlier report to compare against.")
    else:
        L.append(f"{len(regressions)} regression(s), {fixed} criterion(s) newly compliant since the last run.")
    if regressions:
        L += ["", "| Repo | Criterion now failing |", "|---|---|"] + [f"| {n} | {k} |" for n, k in regressions]
    if new:
        L += ["", f"New repositories: {', '.join(new)}"]
    L += ["", "## Compliance by criterion", "", "| Criterion | Compliant | Applicable |", "|---|--:|--:|"]
    for keys in SECTIONS.values():
        for k in keys:
            vals = [r["criteria"][k] for r in repos if r["criteria"][k] is not None]
            L.append(f"| {k} | {sum(1 for v in vals if v)} | {len(vals)} |")
    L += ["", "Full per-repo report: the `report` artifact of this run."]
    (HERE / "drift.md").write_text("\n".join(L) + "\n")
    return len(regressions)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", default="matchory")
    ap.add_argument("--enterprise", default="matchory", help="enterprise slug (needs admin:enterprise); '' skips")
    ap.add_argument("--ttl", type=float, default=12, help="cache TTL in hours")
    ap.add_argument("--refresh", action="store_true", help="ignore cached API responses")
    ap.add_argument("--only", nargs="*", help="audit only these repo names")
    ap.add_argument("--previous", type=Path, help="earlier report.json; writes drift.md with regressions")
    a = ap.parse_args()
    if not shutil.which("zizmor"):
        print("zizmor not found: workflow injection checks skipped (install: `uv tool install zizmor`)", file=sys.stderr)
    gh = GH(a.ttl, a.refresh)
    all_repos = gh.paginate(f"orgs/{a.org}/repos?type=all") or []
    archived = [{"name": x["name"], "visibility": x["visibility"]} for x in all_repos if x["archived"]]
    active = [x for x in all_repos if not x["archived"] and (not a.only or x["name"] in a.only)]
    results, skipped = [], []
    for i, meta in enumerate(sorted(active, key=lambda x: x["name"]), 1):
        print(f"[{i}/{len(active)}] {meta['name']}", file=sys.stderr)
        # the list endpoint omits security_and_analysis; the repo endpoint has it
        _, full = gh.get(f"repos/{meta['full_name']}")
        r = audit_repo(gh, a.org, full or meta)
        if "error" in r:
            print(f"  skipped: {r['error']}", file=sys.stderr)
            skipped.append({"name": meta["name"], "reason": "empty repository" if "409" in r["error"] else r["error"]})
            continue
        r["criteria"] = criteria(r)
        results.append(r)
    results.sort(key=risk)
    write_reports(a.org, audit_org(gh, a.org, a.enterprise), results, sorted(archived, key=lambda x: x["name"]), skipped, gh)
    print(f"wrote {HERE / 'report.md'} and report.json ({gh.calls} API calls)", file=sys.stderr)
    if a.previous:
        print(f"{write_drift(a.previous, results)} regression(s), see drift.md", file=sys.stderr)


if __name__ == "__main__":
    main()
