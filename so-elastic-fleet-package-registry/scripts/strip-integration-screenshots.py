#!/usr/bin/env python3

"""Remove screenshot metadata and assets from Fleet integration archives for all versions EXCEPT for the latest version of an integration available."""

import copy
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path


SCREENSHOTS_KEY = re.compile(r"^(?P<indent>\s*)screenshots:\s*(?:#.*)?$")
ICONS_KEY = re.compile(r"^(?P<indent>\s*)icons:\s*(?:#.*)?$")
SRC_KEY = re.compile(r"^\s*(?:-\s*)?src:\s*(?P<value>[^#\r\n]+)")


def remove_screenshots(manifest):
    """Return a manifest without screenshots sections and their source paths."""
    lines = manifest.splitlines(keepends=True)
    output = []
    sources = []
    index = 0

    while index < len(lines):
        match = SCREENSHOTS_KEY.match(lines[index])
        if not match:
            output.append(lines[index])
            index += 1
            continue

        indent = len(match.group("indent"))
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            source = SRC_KEY.match(line)
            if source:
                value = source.group("value").strip().strip("'\"")
                if value:
                    sources.append(value.lstrip("/"))
            index += 1

    return "".join(output), sources


def icon_paths(manifest):
    """Return image paths referenced by the manifest's icons section."""
    paths = []
    lines = manifest.splitlines()
    index = 0

    while index < len(lines):
        match = ICONS_KEY.match(lines[index])
        if not match:
            index += 1
            continue

        indent = len(match.group("indent"))
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            source = SRC_KEY.match(line)
            if source:
                value = source.group("value").strip().strip("'\"")
                if value:
                    paths.append(value.lstrip("/"))
            index += 1

    return paths


def strip_archive(archive):
    with zipfile.ZipFile(archive, "r") as source:
        manifests = [
            entry.filename
            for entry in source.infolist()
            if entry.filename.endswith("/manifest.yml")
        ]
        # Data-stream manifests may precede the package manifest in the archive.
        manifest_name = min(manifests, key=lambda name: name.count("/"), default=None)
        if manifest_name is None:
            return False, 0, 0

        manifest = source.read(manifest_name).decode("utf-8")
        updated_manifest, screenshot_paths = remove_screenshots(manifest)
        if not screenshot_paths:
            return False, 0, 0
        package_root = manifest_name[: -len("manifest.yml")]
        icons = {package_root + path for path in icon_paths(manifest)}
        excluded = {package_root + path for path in screenshot_paths} - icons
        entries = {entry.filename: entry for entry in source.infolist()}
        removed = excluded & entries.keys()
        removed_bytes = sum(entries[filename].file_size for filename in removed)

        fd, temporary_name = tempfile.mkstemp(dir=archive.parent, suffix=".zip")
        os.close(fd)
        try:
            # mkstemp creates a 0600 file; preserve the registry-readable mode.
            os.chmod(temporary_name, archive.stat().st_mode)
            with zipfile.ZipFile(temporary_name, "w") as target:
                target.comment = source.comment
                for entry in source.infolist():
                    if entry.filename in removed:
                        continue
                    contents = updated_manifest.encode("utf-8") if entry.filename == manifest_name else source.read(entry.filename)
                    target.writestr(copy.copy(entry), contents)
            os.replace(temporary_name, archive)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
    return True, len(removed), removed_bytes


def main():
    storage_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/packages/package-storage")
    compatible_packages_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/compatible-packages.txt")
    versions_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("/versions")
    compatible_packages = set()
    if compatible_packages_file.is_file():
        compatible_packages = {
            package.strip()
            for package in compatible_packages_file.read_text().splitlines()
            if package.strip()
        }
    maintained_packages = set()
    for version_file in versions_dir.glob("*.txt"):
        maintained_packages.update(
            package.strip()
            for package in version_file.read_text().splitlines()
            if package.strip()
        )
    changed = 0
    retained = 0
    removed_files = 0
    removed_bytes = 0
    for archive in sorted(storage_dir.glob("*.zip")):
        if archive.name not in maintained_packages:
            continue
        if archive.name in compatible_packages:
            retained += 1
            continue
        archive_changed, files, bytes_removed = strip_archive(archive)
        if archive_changed:
            archive.with_suffix(archive.suffix + ".sig").unlink(missing_ok=True)
            changed += 1
            removed_files += files
            removed_bytes += bytes_removed
    print(
        f"Stripped {removed_files} screenshot assets ({removed_bytes} bytes) "
        f"from {changed} package archive(s); retained screenshots in "
        f"{retained} latest compatible package archive(s)."
    )


if __name__ == "__main__":
    main()
