#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

import assemble


def manifest(hash_: str, short: str) -> str:
    return f"""version: co.elastic.agent/v1
kind: PackageManifest
package:
    version: 9.4.5
    hash: {hash_}
    versioned-home: data/elastic-agent-{short}
    flavors:
        basic:
            - elastic-otel-collector
            - pf-host-agent
"""


COMMIT = "7a92f7b9479cbfbcb88c94c398660e981dee3d14"


def write_exec(path: Path) -> None:
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class Tree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home = root / "agent"
        self.export = root / "export"
        self.servers = root / "servers"
        self.short = "7a92f7"
        self.components = self.home / "data" / f"elastic-agent-{self.short}" / "components"
        self.components.mkdir(parents=True)
        self.export.mkdir()
        (self.home / assemble.MANIFEST_FILE).write_text(manifest(COMMIT, self.short))
        (self.home / assemble.COMMIT_FILE).write_text(COMMIT + "\n")
        write_exec(self.home / "elastic-agent")
        write_exec(self.components / "elastic-otel-collector")
        (self.components / "elastic-otel-collector.spec.yml").write_text("spec\n")
        write_exec(self.components / "pf-host-agent")
        write_exec(self.export / "fleet-server")
        (self.export / "fleet-server.spec.yml").write_text("spec\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_commit_matches(self):
        self.assertTrue(assemble.commit_matches(COMMIT, COMMIT))
        self.assertTrue(assemble.commit_matches(COMMIT, COMMIT[:6]))
        self.assertFalse(assemble.commit_matches(COMMIT, "0" * 40))
        self.assertFalse(assemble.commit_matches("", COMMIT))

    def test_happy_path_strips_extras_and_uses_versioned_home(self):
        assemble.assemble(self.home, self.export, COMMIT)
        names = sorted(p.name for p in self.components.iterdir())
        self.assertEqual(
            [
                "elastic-otel-collector",
                "elastic-otel-collector.spec.yml",
                "fleet-server",
                "fleet-server.spec.yml",
            ],
            names,
        )
        self.assertTrue(os.access(self.components / "fleet-server", os.X_OK))

    def test_unknown_binary_is_removed(self):
        write_exec(self.components / "brand-new-elastic-thing")
        assemble.assemble(self.home, self.export, COMMIT)
        self.assertFalse((self.components / "brand-new-elastic-thing").exists())

    def test_different_commit_directory(self):
        new_hash = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
        short = "abcdef"
        components = self.home / "data" / f"elastic-agent-{short}" / "components"
        components.mkdir(parents=True)
        write_exec(components / "elastic-otel-collector")
        (components / "elastic-otel-collector.spec.yml").write_text("spec\n")
        (self.home / assemble.MANIFEST_FILE).write_text(manifest(new_hash, short))
        (self.home / assemble.COMMIT_FILE).write_text(new_hash + "\n")
        assemble.assemble(self.home, self.export, new_hash)
        self.assertTrue((components / "fleet-server").is_file())
        self.assertFalse((self.components / "fleet-server").exists())

    def test_commit_mismatch_fails(self):
        with self.assertRaises(assemble.AssembleError):
            assemble.assemble(self.home, self.export, "0" * 40)

    def test_servers_mismatch_fails_before_copy(self):
        self.servers.mkdir()
        (self.servers / assemble.COMMIT_FILE).write_text("1" * 40 + "\n")
        (self.servers / assemble.MANIFEST_FILE).write_text(manifest("1" * 40, "111111"))
        with self.assertRaises(assemble.AssembleError) as raised:
            assemble.assemble(self.home, self.export, COMMIT, also_verify=self.servers)
        self.assertIn("servers", str(raised.exception))
        self.assertFalse((self.components / "fleet-server").exists())

    def test_missing_fleet_export_fails(self):
        (self.export / "fleet-server").unlink()
        with self.assertRaises(assemble.AssembleError):
            assemble.assemble(self.home, self.export, COMMIT)

    def test_missing_otel_fails(self):
        (self.components / "elastic-otel-collector").unlink()
        with self.assertRaises(assemble.AssembleError):
            assemble.assemble(self.home, self.export, COMMIT)

    def test_cli(self):
        self.assertEqual(
            0,
            assemble.main(
                [
                    "--agent-home",
                    str(self.home),
                    "--agent-commit",
                    COMMIT,
                    "--fleet-export",
                    str(self.export),
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
