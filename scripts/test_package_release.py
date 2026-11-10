"""Checks for lossless third-party notice collection and dev-only exclusion."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from package_release import copy_notices


class NoticeTests(unittest.TestCase):
    def test_transitive_notices_and_additional_license_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = []
            for name, licenses in {
                "runtime": {"LICENSE-MIT": "runtime copyright\n", "NOTICE": "additional notice\n"},
                "unicode": {"LICENSE-MIT": "unicode copyright\n", "LICENSE-UNICODE": "Unicode-3.0\n"},
                "dev-only": {"LICENSE-MIT": "excluded dev dependency\n"},
            }.items():
                source = root / name
                source.mkdir()
                for filename, text in licenses.items():
                    (source / filename).write_text(text)
                packages.append({"id": name, "name": name, "version": "1.0",
                                 "manifest_path": str(source / "Cargo.toml"),
                                 "license": "MIT", "license_file": None})
            def edge(name, kind=None):
                return {"pkg": name, "dep_kinds": [{"kind": kind}]}
            metadata = {"packages": packages, "resolve": {
                "root": "application", "nodes": [
                    {"id": "application", "deps": [edge("runtime"), edge("dev-only", "dev")]},
                    {"id": "runtime", "deps": [edge("unicode", "build")]},
                    {"id": "unicode", "deps": []}, {"id": "dev-only", "deps": []},
                ]}}
            rust = root / "rust/share/doc/rust"
            (rust / "licenses").mkdir(parents=True)
            (rust / "COPYRIGHT-library.html").write_text("standard library notice\n")
            (rust / "licenses/MIT.txt").write_text("Rust MIT text\n")
            destination = root / "collected"
            destination.mkdir()
            with patch("package_release.output", return_value=str(root / "rust")):
                inventory = copy_notices(destination, metadata)
            self.assertEqual([item["name"] for item in inventory], ["runtime", "unicode"])
            self.assertEqual((destination / "runtime-1.0/NOTICE").read_text(), "additional notice\n")
            self.assertEqual((destination / "unicode-1.0/LICENSE-UNICODE").read_text(), "Unicode-3.0\n")
            self.assertEqual((destination / "unicode-1.0/LICENSE-MIT").read_text(), "unicode copyright\n")
            self.assertFalse((destination / "dev-only-1.0").exists())
            self.assertEqual(json.loads((destination / "inventory.json").read_text()), inventory)


if __name__ == "__main__":
    unittest.main()
