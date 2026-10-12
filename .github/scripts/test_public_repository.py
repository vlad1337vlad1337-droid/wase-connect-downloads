"""Security boundaries use synthetic fixtures; never include live secrets."""
import json
import tempfile
import unittest
from pathlib import Path

from check_public_repository import ROOT_FILES, audit, validate_status


class PublicRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.status = {
            "schemaVersion": 1, "publicStableRelease": None, "downloads": [],
            "status": "preparing", "updatedAt": "2026-10-12", "reason": "Acceptance pending",
        }
        for name in ROOT_FILES:
            self.write(name, "# Documentation\n")
        self.write("release-status.json", json.dumps(self.status))

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def issues(self):
        paths = [path.relative_to(self.root) for path in self.root.rglob("*") if path.is_file() or path.is_symlink()]
        return audit(self.root, paths)["issues"]

    def test_clean_documentation(self):
        self.assertEqual(self.issues(), [])

    def test_application_source_rejected(self):
        for name in ["src/main.cpp", "docs/main.qml", ".github/scripts/client.py", "assets/client.exe"]:
            with self.subTest(name=name):
                self.write(name, "synthetic")
                self.assertTrue(any(issue["file"] == name for issue in self.issues()))
                (self.root / name).unlink()

    def test_ci_tools_allowed_only_by_exact_path(self):
        self.write(".github/scripts/check_public_repository.py", "# CI validation only\n")
        self.write(".github/scripts/test_public_repository.py", "# CI test only\n")
        self.assertEqual(self.issues(), [])

    def test_secret_reports_no_value(self):
        token = "ghp_" + "a" * 36
        self.write("README.md", token)
        findings = self.issues()
        self.assertTrue(any(issue["error"] == "GitHub token" for issue in findings))
        self.assertNotIn(token, json.dumps(findings))

    def test_private_links_and_personal_paths(self):
        private_url = "https://github.com/vlad1337vlad1337-droid/" + "wase-connect/"
        local = "/" + "Users/test-user/report.txt"
        self.write("README.md", private_url + "\n" + local)
        self.assertEqual(len(self.issues()), 2)

    def test_missing_local_link(self):
        self.write("README.md", "[Guide](docs/missing.md)")
        self.assertTrue(any("link target missing" in issue["error"] for issue in self.issues()))

    def test_relative_local_link(self):
        self.write("docs/guide.md", "[Home](../README.md)\n[Web](https://example.org)")
        self.assertEqual(self.issues(), [])

    def test_symlink_rejected(self):
        (self.root / "docs").mkdir()
        (self.root / "docs/link.md").symlink_to(self.root / "README.md")
        self.assertTrue(any("symlinks" in issue["error"] for issue in self.issues()))

    def test_binary_disguised_as_text(self):
        (self.root / "README.md").write_bytes(b"\xff\x00")
        self.assertTrue(any("UTF-8" in issue["error"] for issue in self.issues()))

    def test_control_bytes_disguised_as_text(self):
        (self.root / "README.md").write_bytes(b"ELF\x00\x01")
        self.assertTrue(any("binary/control" in issue["error"] for issue in self.issues()))

    def test_active_svg_rejected(self):
        self.write("assets/test.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
        self.assertTrue(any("active SVG" in issue["error"] for issue in self.issues()))

    def test_external_svg_rejected(self):
        self.write("assets/test.svg", '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.org/image.png"/></svg>')
        self.assertTrue(any("external resource" in issue["error"] for issue in self.issues()))

    def test_external_svg_stylesheet_rejected(self):
        self.write("assets/test.svg", '<svg xmlns="http://www.w3.org/2000/svg"><style>@import "https://example.org/style.css";</style></svg>')
        self.assertTrue(any("external stylesheet" in issue["error"] for issue in self.issues()))

    def test_premature_release_rejected(self):
        for key, value in [("downloads", ["installer.exe"]), ("publicStableRelease", "2.1.7"), ("status", "available")]:
            with self.subTest(key=key):
                self.assertTrue(validate_status({**self.status, key: value}))

    def test_unknown_status_field_and_invalid_date(self):
        self.assertTrue(validate_status({**self.status, "privateDownload": "hidden"}))
        self.assertTrue(validate_status({**self.status, "updatedAt": "2026-02-31"}))


if __name__ == "__main__":
    unittest.main()
