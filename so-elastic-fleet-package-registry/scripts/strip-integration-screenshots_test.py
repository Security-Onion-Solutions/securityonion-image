from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SCRIPT = Path(os.environ.get("SCREENSHOT_SCRIPT", Path(__file__).with_name("strip-integration-screenshots.py")))
SPEC = importlib.util.spec_from_file_location("strip_integration_screenshots", SCRIPT)
screenshots = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(screenshots)


class TestStripIntegrationScreenshots(unittest.TestCase):

    manifest = """name: test
icons:
  - src: /img/icon.png
screenshots:
  - src: /img/screenshot.png
    title: Screenshot
"""

    def create_archive(self, directory, name, manifest=None, files=None):
        archive = directory / name
        with zipfile.ZipFile(archive, "w") as target:
            if manifest is not None:
                target.writestr(f"{name[:-4]}/manifest.yml", manifest)
            for filename, contents in (files or {}).items():
                target.writestr(f"{name[:-4]}/{filename}", contents)
        return archive

    def archive_contents(self, archive):
        with zipfile.ZipFile(archive) as source:
            return source.namelist(), source.read(f"{archive.stem}/manifest.yml").decode()

    def test_remove_screenshots(self):
        manifest = """name: test
screenshots: # remove this
  - src: '/img/one.png'
  - src: \"/img/two.jpg\"
next: value
"""
        updated, paths = screenshots.remove_screenshots(manifest)

        self.assertEqual("name: test\nnext: value\n", updated)
        self.assertEqual(["img/one.png", "img/two.jpg"], paths)

    def test_icon_paths(self):
        manifest = """icons:
  - src: /img/one.png
  - src: 'img/two.svg'
next: value
"""

        self.assertEqual(["img/one.png", "img/two.svg"], screenshots.icon_paths(manifest))

    def test_strip_archive_removes_declared_screenshots_preserves_icons_and_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = """name: test
icons:
  - src: /img/icon.png
screenshots:
  - src: /img/screenshot.png
  - src: /assets/screenshot.svg
"""
            archive = self.create_archive(
                directory,
                "old-1.0.0.zip",
                manifest,
                {
                    "data_stream/test/manifest.yml": "type: logs\n",
                    "img/icon.png": b"icon",
                    "img/screenshot.png": b"screenshot",
                    "assets/screenshot.svg": b"svg",
                    "img/unrelated.jpg": b"jpg",
                    "img/vector.svg": b"vector",
                },
            )
            archive.chmod(0o644)

            changed, removed, removed_bytes = screenshots.strip_archive(archive)
            names, manifest = self.archive_contents(archive)

            self.assertTrue(changed)
            self.assertEqual(2, removed)
            self.assertEqual(len(b"screenshot") + len(b"svg"), removed_bytes)
            self.assertNotIn("screenshots:", manifest)
            self.assertIn("old-1.0.0/img/icon.png", names)
            self.assertIn("old-1.0.0/img/vector.svg", names)
            self.assertNotIn("old-1.0.0/img/screenshot.png", names)
            self.assertNotIn("old-1.0.0/assets/screenshot.svg", names)
            self.assertIn("old-1.0.0/img/unrelated.jpg", names)
            self.assertEqual(0o644, stat.S_IMODE(archive.stat().st_mode))

    def test_strip_archive_without_changes_or_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            no_screenshots = self.create_archive(
                directory,
                "plain-1.0.0.zip",
                "name: plain\n",
                {"img/unrelated.jpg": b"image"},
            )
            no_manifest = self.create_archive(directory, "invalid-1.0.0.zip", files={"readme": b"text"})

            self.assertEqual((False, 0, 0), screenshots.strip_archive(no_screenshots))
            self.assertEqual((False, 0, 0), screenshots.strip_archive(no_manifest))
            self.assertIn("plain-1.0.0/img/unrelated.jpg", self.archive_contents(no_screenshots)[0])

    def test_strip_archive_removes_temporary_archive_when_replace_does_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.create_archive(
                Path(temporary),
                "old-1.0.0.zip",
                self.manifest,
                {"img/icon.png": b"icon", "img/screenshot.png": b"screenshot"},
            )

            with patch.object(screenshots.os, "replace"):
                screenshots.strip_archive(archive)

            self.assertEqual(1, len(list(archive.parent.glob("*.zip"))))

    def test_main_removes_signature_when_screenshot_asset_is_missing_or_an_icon(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage_dir = root / "packages"
            versions_dir = root / "versions"
            storage_dir.mkdir()
            versions_dir.mkdir()
            (versions_dir / "9.3.7.txt").write_text("old-1.0.0.zip\n")
            manifest = """icons:
  - src: /img/icon.png
screenshots:
  - src: /img/icon.png
  - src: /missing.png
"""
            old = self.create_archive(storage_dir, "old-1.0.0.zip", manifest, {"img/icon.png": b"icon"})
            old.with_suffix(".zip.sig").write_text("signature")
            original_argv = sys.argv
            try:
                sys.argv = [str(SCRIPT), str(storage_dir), str(root / "missing.txt"), str(versions_dir)]
                with redirect_stdout(StringIO()):
                    screenshots.main()
            finally:
                sys.argv = original_argv

            names, updated_manifest = self.archive_contents(old)
            self.assertNotIn("screenshots:", updated_manifest)
            self.assertIn("old-1.0.0/img/icon.png", names)
            self.assertFalse(old.with_suffix(".zip.sig").exists())

    def test_main_only_strips_maintained_non_latest_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage_dir = root / "packages"
            versions_dir = root / "versions"
            storage_dir.mkdir()
            versions_dir.mkdir()
            compatible = root / "compatible-packages.txt"
            compatible.write_text("latest-1.0.0.zip\n")
            (versions_dir / "9.3.7.txt").write_text("latest-1.0.0.zip\nold-1.0.0.zip\n")
            latest = self.create_archive(storage_dir, "latest-1.0.0.zip", self.manifest, {"img/icon.png": b"icon", "img/screenshot.png": b"latest"})
            old = self.create_archive(storage_dir, "old-1.0.0.zip", self.manifest, {"img/icon.png": b"icon", "img/screenshot.png": b"old"})
            unmaintained = self.create_archive(storage_dir, "other-1.0.0.zip", self.manifest, {"img/icon.png": b"icon", "img/screenshot.png": b"other"})
            old.with_suffix(".zip.sig").write_text("signature")
            original_argv = sys.argv
            try:
                sys.argv = [str(SCRIPT), str(storage_dir), str(compatible), str(versions_dir)]
                output = StringIO()
                with redirect_stdout(output):
                    screenshots.main()
            finally:
                sys.argv = original_argv

            self.assertIn("Stripped 1 screenshot assets (3 bytes) from 1 package archive(s)", output.getvalue())
            self.assertIn("retained screenshots in 1 latest compatible package archive(s)", output.getvalue())
            self.assertNotIn("screenshots:", self.archive_contents(old)[1])
            self.assertFalse(old.with_suffix(".zip.sig").exists())
            self.assertIn("screenshots:", self.archive_contents(latest)[1])
            self.assertIn("screenshots:", self.archive_contents(unmaintained)[1])

    def test_main_allows_missing_compatible_package_list(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage_dir = root / "packages"
            versions_dir = root / "versions"
            storage_dir.mkdir()
            versions_dir.mkdir()
            (versions_dir / "9.3.7.txt").write_text("old-1.0.0.zip\n")
            old = self.create_archive(storage_dir, "old-1.0.0.zip", self.manifest, {"img/icon.png": b"icon", "img/screenshot.png": b"old"})
            original_argv = sys.argv
            try:
                sys.argv = [str(SCRIPT), str(storage_dir), str(root / "missing.txt"), str(versions_dir)]
                with redirect_stdout(StringIO()):
                    screenshots.main()
            finally:
                sys.argv = original_argv

            self.assertNotIn("screenshots:", self.archive_contents(old)[1])
