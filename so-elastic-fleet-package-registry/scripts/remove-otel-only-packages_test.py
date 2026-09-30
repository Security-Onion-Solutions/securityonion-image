from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


SCRIPT = Path(os.environ.get("OTEL_SCRIPT", Path(__file__).with_name("remove-otel-only-packages.py")))
SPEC = importlib.util.spec_from_file_location("remove_otel_only_packages", SCRIPT)
otel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(otel)


OTEL_INTEGRATION = """format_version: 3.6.0
name: otel_integration
type: integration
policy_templates:
  - name: otel_integration
    inputs:
      - type: otelcol
"""
OTEL_DATA_STREAM = """title: Events
type: logs
streams:
  - input: otelcol
"""
OTEL_INPUT = """format_version: 3.5.0
name: otel_input
type: input
policy_templates:
  - name: otel_input
    type: logs
    input: otelcol
"""
MIXED_INTEGRATION = """name: mixed
type: integration
policy_templates:
  - name: mixed
    inputs:
      - type: otelcol
      - type: filestream
"""
FILESTREAM_DATA_STREAM = """type: logs
streams:
  - input: filestream
"""
CONTENT = """name: content
type: content
"""


class TestRemoveOtelOnlyPackages(unittest.TestCase):

    def create_archive(self, directory, name, manifest, files=None):
        archive = directory / name
        with zipfile.ZipFile(archive, "w") as target:
            # Write data stream manifests first to match archives where they precede the package manifest.
            for filename, contents in (files or {}).items():
                target.writestr(f"{name[:-4]}/{filename}", contents)
            target.writestr(f"{name[:-4]}/manifest.yml", manifest)
        return archive

    def run_main(self, storage_dir, versions_dir):
        original_argv = sys.argv
        output = StringIO()
        try:
            sys.argv = [str(SCRIPT), str(storage_dir), str(versions_dir)]
            with redirect_stdout(output):
                otel.main()
        finally:
            sys.argv = original_argv
        return output.getvalue()

    def test_package_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            integration = self.create_archive(directory, "otel_integration-1.0.0.zip", OTEL_INTEGRATION, {"data_stream/events/manifest.yml": OTEL_DATA_STREAM})
            input_package = self.create_archive(directory, "otel_input-1.0.0.zip", OTEL_INPUT)
            mixed = self.create_archive(directory, "mixed-1.0.0.zip", MIXED_INTEGRATION, {"data_stream/log/manifest.yml": FILESTREAM_DATA_STREAM})
            empty = self.create_archive(directory, "empty-1.0.0.zip", "", {"data_stream/empty/manifest.yml": ""})

            self.assertEqual({"otelcol"}, otel.package_inputs(integration))
            self.assertEqual({"otelcol"}, otel.package_inputs(input_package))
            self.assertEqual({"otelcol", "filestream"}, otel.package_inputs(mixed))
            self.assertEqual(set(), otel.package_inputs(empty))

    def test_data_stream_input_prevents_removal(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.create_archive(
                Path(temporary),
                "partial-1.0.0.zip",
                OTEL_INTEGRATION,
                {"data_stream/events/manifest.yml": OTEL_DATA_STREAM, "data_stream/log/manifest.yml": FILESTREAM_DATA_STREAM},
            )

            self.assertFalse(otel.is_otel_only(archive))

    def test_is_otel_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)

            self.assertTrue(otel.is_otel_only(self.create_archive(directory, "otel_input-1.0.0.zip", OTEL_INPUT)))
            self.assertFalse(otel.is_otel_only(self.create_archive(directory, "mixed-1.0.0.zip", MIXED_INTEGRATION)))
            self.assertFalse(otel.is_otel_only(self.create_archive(directory, "content-1.0.0.zip", CONTENT)))

    def test_main_removes_otel_only_packages_and_keeps_maintained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage_dir = root / "packages"
            versions_dir = root / "versions"
            storage_dir.mkdir()
            versions_dir.mkdir()
            (versions_dir / "9.3.7.txt").write_text("otel_input-0.9.0.zip\n\n")
            removed = self.create_archive(storage_dir, "otel_input-1.0.0.zip", OTEL_INPUT)
            removed.with_suffix(".zip.sig").write_text("signature")
            unsigned = self.create_archive(storage_dir, "otel_integration-1.0.0.zip", OTEL_INTEGRATION, {"data_stream/events/manifest.yml": OTEL_DATA_STREAM})
            maintained = self.create_archive(storage_dir, "otel_input-0.9.0.zip", OTEL_INPUT)
            mixed = self.create_archive(storage_dir, "mixed-1.0.0.zip", MIXED_INTEGRATION)
            content = self.create_archive(storage_dir, "content-1.0.0.zip", CONTENT)

            output = self.run_main(storage_dir, versions_dir)

            self.assertFalse(removed.exists())
            self.assertFalse(removed.with_suffix(".zip.sig").exists())
            self.assertFalse(unsigned.exists())
            self.assertTrue(maintained.exists())
            self.assertTrue(mixed.exists())
            self.assertTrue(content.exists())
            self.assertIn("Removing otelcol-only package: otel_input-1.0.0.zip", output)
            self.assertIn("Keeping maintained otelcol-only package: otel_input-0.9.0.zip", output)
            self.assertIn("Removed 2 otelcol-only package archive(s); kept 1 maintained otelcol-only package archive(s).", output)

    def test_missing_versions_directory_still_removes_otel_only_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage_dir = root / "packages"
            storage_dir.mkdir()
            archive = self.create_archive(storage_dir, "otel_input-1.0.0.zip", OTEL_INPUT)

            output = self.run_main(storage_dir, root / "missing-versions")

            self.assertFalse(archive.exists())
            self.assertIn("Removed 1 otelcol-only package archive(s); kept 0 maintained otelcol-only package archive(s).", output)

    def test_empty_versions_directory_removes_otel_only_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage_dir = root / "packages"
            versions_dir = root / "versions"
            storage_dir.mkdir()
            versions_dir.mkdir()
            archive = self.create_archive(storage_dir, "otel_input-1.0.0.zip", OTEL_INPUT)

            output = self.run_main(storage_dir, versions_dir)

            self.assertFalse(archive.exists())
            self.assertIn("Removed 1 otelcol-only package archive(s); kept 0 maintained otelcol-only package archive(s).", output)
