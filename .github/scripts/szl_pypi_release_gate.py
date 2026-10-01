#!/usr/bin/env python3
"""SZL PyPI release gate — build, verify, and bind a distribution to its git tag.

Canonical file: identical bytes in every szl-holdings repository that publishes
to PyPI. Runs in the `build` job of `.github/workflows/publish-pypi.yml`:

  * on pull_request / push  -> builds and gates every declared package (readiness)
  * on release (published)  -> selects the package named by the tag, requires
                               tag == v{version} (single package) or
                               {name}-v{version} (multi-package repo), refuses
                               versions that already exist on PyPI, and emits
                               `dist/` plus a JSON receipt for the publish job.

Fails closed. Nothing here talks to PyPI with credentials; publication happens
only in the separate `publish` job through Trusted Publishing (OIDC).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
import zipfile
from email.parser import HeaderParser
from pathlib import Path

FORBIDDEN_TOP_LEVEL = {"tests", "test", "docs", "examples", "example", "scripts", "benchmarks", "build", "dist", "out", "data", "payload", "fixtures"}
PRIVATE_CLASSIFIER = "Private :: Do Not Upload"


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, **kw)


def fail(msg: str) -> None:
    print(f"::error::{msg}", flush=True)
    sys.exit(1)


def warn(msg: str) -> None:
    print(f"::warning::{msg}", flush=True)


def parse_packages(spec: str) -> list[dict]:
    pkgs = []
    for item in [s.strip() for s in spec.split(";") if s.strip()]:
        name, _, rest = item.partition("=")
        directory, _, env = rest.partition(":")
        pkgs.append({"name": name.strip(), "dir": (directory or ".").strip(), "environment": (env or "pypi").strip()})
    if not pkgs:
        fail("SZL_PACKAGES is empty")
    return pkgs


def pypi_versions(name: str) -> set[str] | None:
    req = urllib.request.Request(f"https://pypi.org/pypi/{norm(name)}/json", headers={"User-Agent": "szl-pypi-release-gate/1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return set(json.loads(r.read())["releases"].keys())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return set()
        warn(f"PyPI lookup for {name} failed: HTTP {e.code}")
        return None
    except Exception as e:  # network trouble is not a reason to publish blindly on release
        warn(f"PyPI lookup for {name} failed: {e}")
        return None


def read_metadata(wheel: Path) -> dict:
    with zipfile.ZipFile(wheel) as z:
        meta_name = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        msg = HeaderParser().parsestr(z.read(meta_name).decode("utf-8", "replace"))
        top = sorted({n.split("/")[0] for n in z.namelist() if not n.split("/")[0].endswith(".dist-info")})
        py_files = [n for n in z.namelist() if n.endswith(".py")]
    return {"msg": msg, "top_level": top, "py_count": len(py_files)}


def gate_package(pkg: dict, repo: str, event: str, ref_type: str, ref_name: str, outdir: Path) -> dict:
    pdir = Path(pkg["dir"]).resolve()
    pyproject = pdir / "pyproject.toml"
    if not pyproject.is_file():
        fail(f"{pkg['name']}: {pyproject} not found")
    with open(pyproject, "rb") as f:
        pp = tomllib.load(f)
    project = pp.get("project") or {}
    release_cfg = ((pp.get("tool") or {}).get("szl") or {}).get("release") or {}

    if norm(project.get("name", "")) != norm(pkg["name"]):
        fail(f"{pkg['name']}: pyproject [project].name is {project.get('name')!r}, expected {pkg['name']!r}")
    if PRIVATE_CLASSIFIER in (project.get("classifiers") or []):
        fail(f"{pkg['name']}: carries '{PRIVATE_CLASSIFIER}' — not a publishable package")
    if not (pp.get("build-system") or {}).get("build-backend"):
        fail(f"{pkg['name']}: pyproject has no [build-system].build-backend (PEP 517 backend must be explicit)")
    for key in ("description", "readme", "requires-python"):
        if not project.get(key):
            fail(f"{pkg['name']}: [project].{key} is required")
    if not (project.get("license") or project.get("license-files")):
        fail(f"{pkg['name']}: [project].license (or license-files) is required")
    urls = project.get("urls") or {}
    source_url = urls.get("Source") or urls.get("Repository") or urls.get("Source Code")
    expected_prefix = f"https://github.com/{repo}"
    if not source_url or not source_url.rstrip("/").lower().startswith(expected_prefix.lower()):
        fail(f"{pkg['name']}: [project.urls] must carry Source/Repository = {expected_prefix} (got {source_url!r}); PyPI verifies this against the Trusted Publisher")

    # Build into a per-package staging dir, then verify.
    stage = outdir.parent / f"stage-{norm(pkg['name'])}"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    sh([sys.executable, "-m", "build", "--outdir", str(stage), str(pdir)])
    files = sorted(stage.iterdir())
    wheels = [f for f in files if f.suffix == ".whl"]
    sdists = [f for f in files if f.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1:
        fail(f"{pkg['name']}: expected exactly one wheel and one sdist, got {[f.name for f in files]}")
    sh([sys.executable, "-m", "twine", "check", "--strict", *[str(f) for f in files]])

    meta = read_metadata(wheels[0])
    msg = meta["msg"]
    version = msg["Version"]
    if norm(msg["Name"]) != norm(pkg["name"]):
        fail(f"{pkg['name']}: built metadata Name={msg['Name']!r} does not match")
    if meta["py_count"] == 0:
        fail(f"{pkg['name']}: wheel contains no Python files — packaging is misconfigured")
    bad_top = sorted(set(meta["top_level"]) & FORBIDDEN_TOP_LEVEL)
    if bad_top:
        fail(f"{pkg['name']}: wheel leaks non-package top-level entries {bad_top}; fix package discovery")
    declared = release_cfg.get("import_names")
    if declared:
        actual = {t[:-3] if t.endswith(".py") else t for t in meta["top_level"]}
        if actual != set(declared):
            fail(f"{pkg['name']}: wheel top-level names {sorted(actual)} != declared [tool.szl.release].import_names {sorted(declared)}")
    if not msg.get_all("Project-URL"):
        fail(f"{pkg['name']}: built metadata has no Project-URL entries")

    # Tag binding (release only) and PyPI collision check.
    tag_expect_single = f"v{version}"
    tag_expect_multi = f"{norm(pkg['name'])}-v{version}"
    if event == "release":
        if ref_type != "tag":
            fail(f"release event on non-tag ref {ref_type}:{ref_name}")
        if ref_name not in (tag_expect_single, tag_expect_multi):
            fail(f"{pkg['name']}: tag {ref_name!r} does not match built version {version!r} (expected {tag_expect_single!r} or {tag_expect_multi!r})")
    existing = pypi_versions(pkg["name"])
    if existing is None and event == "release":
        fail(f"{pkg['name']}: could not confirm PyPI release list; refusing to publish blind")
    if existing and version in existing:
        if event == "release":
            fail(f"{pkg['name']}=={version} already exists on PyPI; bump [project].version before releasing")
        warn(f"{pkg['name']}=={version} already exists on PyPI; a release will require a version bump")

    # Smoke-install the wheel in isolation and import-check the declared names.
    venv = outdir.parent / f"venv-{norm(pkg['name'])}"
    shutil.rmtree(venv, ignore_errors=True)
    sh([sys.executable, "-m", "venv", str(venv)])
    vpy = venv / ("Scripts" if os.name == "nt" else "bin") / "python"
    sh([str(vpy), "-m", "pip", "install", "--disable-pip-version-check", "-q", str(wheels[0])])
    sh([str(vpy), "-c", f"import importlib.metadata as m; assert m.version({pkg['name']!r}) == {version!r}, m.version({pkg['name']!r})"])
    for mod in declared or []:
        sh([str(vpy), "-c", f"import importlib; importlib.import_module({mod!r})"])

    outdir.mkdir(parents=True, exist_ok=True)
    receipt = {"package": pkg["name"], "version": version, "environment": pkg["environment"], "event": event, "ref": f"{ref_type}:{ref_name}",
               "repository": repo, "source_sha": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
               "files": {}, "top_level": meta["top_level"]}
    for f in files:
        receipt["files"][f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
        shutil.copy2(f, outdir / f.name)
    print(json.dumps(receipt, indent=2))
    return receipt


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packages", required=True, help="name=dir[:environment];name2=dir2[:environment]")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--event", required=True)
    ap.add_argument("--ref-type", required=True)
    ap.add_argument("--ref-name", required=True)
    ap.add_argument("--outdir", default="dist")
    args = ap.parse_args()

    pkgs = parse_packages(args.packages)
    outdir = Path(args.outdir).resolve()
    shutil.rmtree(outdir, ignore_errors=True)

    if args.event == "release":
        if len(pkgs) == 1:
            selected = pkgs
        else:
            m = re.match(r"^(?P<name>.+?)-v(?P<ver>\d.*)$", args.ref_name)
            if not m:
                fail(f"multi-package repository: tag must be <package>-v<version>, got {args.ref_name!r}")
            selected = [p for p in pkgs if norm(p["name"]) == norm(m.group("name"))]
            if len(selected) != 1:
                fail(f"tag {args.ref_name!r} names no declared package; declared: {[p['name'] for p in pkgs]}")
    else:
        selected = pkgs

    receipts = []
    for pkg in selected:
        pkg_out = outdir if args.event == "release" else outdir / norm(pkg["name"])
        receipts.append(gate_package(pkg, args.repo, args.event, args.ref_type, args.ref_name, pkg_out))

    (outdir.parent / "release-gate.json").write_text(json.dumps(receipts, indent=2))
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out and args.event == "release":
        r = receipts[0]
        with open(gh_out, "a") as f:
            f.write(f"package={r['package']}\nversion={r['version']}\nenvironment={r['environment']}\n")
    print(f"release gate PASS for {[r['package'] + '==' + r['version'] for r in receipts]}")


if __name__ == "__main__":
    main()
