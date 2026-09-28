#!/usr/bin/env python3
"""Copy fleet-server onto official slim and leave only the components we ship.

On an Elastic version bump, update AGENT_COMMIT in the Dockerfile. Edit KEEP
below only if we need a new component (or a rename).

  python3 -m unittest discover -s scripts -v
"""

from __future__ import annotations

import argparse
import os
import pwd
import re
import shutil
import sys
from pathlib import Path

AGENT_USER = "elastic-agent"
COMMIT_FILE = ".elastic-agent.active.commit"
MANIFEST_FILE = "manifest.yaml"

# Components that remain in the image. Everything else in components/ is deleted.
KEEP = {
    "elastic-otel-collector",
    "elastic-otel-collector.spec.yml",
    "fleet-server",
    "fleet-server.spec.yml",
}

HASH_RE = re.compile(r"(?m)^[ \t]+hash:[ \t]+(\S+)[ \t]*$")
VERSIONED_HOME_RE = re.compile(r"(?m)^[ \t]+versioned-home:[ \t]+(\S+)[ \t]*$")


class AssembleError(Exception):
    pass


def commit_matches(expected: str, got: str) -> bool:
    expected = (expected or "").strip()
    got = (got or "").strip()
    return bool(expected and got and (got.startswith(expected) or expected.startswith(got)))


def versioned_home(manifest_text: str) -> tuple[str, str]:
    """Return (package.hash, versioned-home) from manifest.yaml."""
    hashes = HASH_RE.findall(manifest_text)
    homes = VERSIONED_HOME_RE.findall(manifest_text)
    if not hashes:
        raise AssembleError("manifest.yaml: missing package.hash")
    if not homes:
        raise AssembleError("manifest.yaml: missing package.versioned-home")
    home = homes[0]
    if Path(home).is_absolute() or ".." in Path(home).parts:
        raise AssembleError(f"manifest.yaml: unsafe versioned-home {home!r}")
    return hashes[0], home


def verify_commit(agent_home: Path, expected: str, role: str) -> None:
    expected = (expected or "").strip()
    if not expected:
        raise AssembleError("AGENT_COMMIT is required")
    commit_path = agent_home / COMMIT_FILE
    try:
        active = commit_path.read_text().strip()
        pkg_hash, _ = versioned_home((agent_home / MANIFEST_FILE).read_text())
    except OSError as exc:
        raise AssembleError(f"{role}: {exc}") from exc
    if not commit_matches(expected, active):
        raise AssembleError(f"{role} {COMMIT_FILE} mismatch: expected {expected} got {active}")
    if not commit_matches(expected, pkg_hash):
        raise AssembleError(f"{role} package.hash mismatch: expected {expected} got {pkg_hash}")
    print(f"{role} commit ok: {active}")


def _chown_agent(path: Path) -> None:
    try:
        pw = pwd.getpwnam(AGENT_USER)
    except KeyError:
        return
    os.chown(path, pw.pw_uid, pw.pw_gid)


def _copy(src: Path, dest: Path, mode: int) -> None:
    if not src.is_file():
        raise AssembleError(f"missing {src}")
    shutil.copy2(src, dest)
    os.chmod(dest, mode)
    _chown_agent(dest)


def _require_exec(path: Path) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise AssembleError(f"missing executable: {path}")


def assemble(agent_home: Path, fleet_export: Path, expected_commit: str, also_verify: Path | None = None) -> Path:
    verify_commit(agent_home, expected_commit, "slim")
    if also_verify is not None:
        verify_commit(also_verify, expected_commit, "servers")

    _, home = versioned_home((agent_home / MANIFEST_FILE).read_text())
    components = agent_home / home / "components"
    if not components.is_dir():
        raise AssembleError(f"components directory missing: {components}")

    _copy(fleet_export / "fleet-server", components / "fleet-server", 0o755)
    _copy(fleet_export / "fleet-server.spec.yml", components / "fleet-server.spec.yml", 0o644)

    for path in list(components.iterdir()):
        if path.name not in KEEP:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()

    _require_exec(agent_home / "elastic-agent")
    for name in ("elastic-otel-collector", "fleet-server"):
        _require_exec(components / name)
    if not (components / "fleet-server.spec.yml").is_file():
        raise AssembleError("missing fleet-server.spec.yml")

    leftover = sorted(p.name for p in components.iterdir())
    unexpected = set(leftover) - KEEP
    if unexpected:
        raise AssembleError("unexpected components remain: " + ", ".join(sorted(unexpected)))

    print("=== components ===")
    for path in sorted(components.iterdir()):
        print(f"{path.stat().st_size:>12} {path}")
    return components


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-home", type=Path, required=True)
    parser.add_argument("--agent-commit", required=True)
    parser.add_argument("--fleet-export", type=Path, required=True)
    parser.add_argument("--also-verify", type=Path)
    args = parser.parse_args(argv)
    try:
        assemble(args.agent_home, args.fleet_export, args.agent_commit, args.also_verify)
        return 0
    except AssembleError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
