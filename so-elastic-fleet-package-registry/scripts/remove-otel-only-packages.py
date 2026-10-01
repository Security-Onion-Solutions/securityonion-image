#!/usr/bin/env python3
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""Remove integration and input packages that only collect data through the OpenTelemetry collector (otelcol) input.

Fleet will not add otelcol inputs to an agent policy that uses a Logstash output, which Security Onion uses for all
agent policies. Archives listed in /versions/*.txt are kept; remove them from those files to drop them from the image.
"""

import sys
import zipfile
from pathlib import Path

import yaml


OTEL_INPUT = "otelcol"


def package_inputs(archive):
    """Return the set of input types declared by a package archive's manifests."""
    inputs = set()
    with zipfile.ZipFile(archive, "r") as source:
        manifests = [name for name in source.namelist() if name.endswith("/manifest.yml")]
        # Data-stream manifests may precede the package manifest in the archive.
        package_manifest = min(manifests, key=lambda name: name.count("/"), default=None)
        for name in manifests:
            manifest = yaml.safe_load(source.read(name)) or {}
            if name == package_manifest:
                for template in manifest.get("policy_templates") or []:
                    # Input packages declare a single input, integration packages declare a list of inputs.
                    if template.get("input"):
                        inputs.add(template["input"])
                    inputs.update(item["type"] for item in template.get("inputs") or [] if item.get("type"))
            else:
                inputs.update(stream["input"] for stream in manifest.get("streams") or [] if stream.get("input"))
    return inputs


def is_otel_only(archive):
    inputs = package_inputs(archive)
    return bool(inputs) and inputs == {OTEL_INPUT}


def main():
    storage_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/packages/package-storage")
    versions_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/versions")
    maintained_packages = set()
    for version_file in versions_dir.glob("*.txt"):
        maintained_packages.update(
            package.strip()
            for package in version_file.read_text().splitlines()
            if package.strip()
        )
    removed = 0
    retained = 0
    for archive in sorted(storage_dir.glob("*.zip")):
        if not is_otel_only(archive):
            continue
        if archive.name in maintained_packages:
            print(f"Keeping maintained otelcol-only package: {archive.name}")
            retained += 1
            continue
        print(f"Removing otelcol-only package: {archive.name}")
        archive.unlink()
        archive.with_suffix(archive.suffix + ".sig").unlink(missing_ok=True)
        removed += 1
    print(f"Removed {removed} otelcol-only package archive(s); kept {retained} maintained otelcol-only package archive(s).")


if __name__ == "__main__":  # pragma: no cover
    main()
