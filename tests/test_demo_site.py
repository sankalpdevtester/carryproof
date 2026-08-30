from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from html.parser import HTMLParser
from pathlib import Path

import build
import carryproof as cp
from demo.build_site import build_site, insert_before


class PageTags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


class PublicDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="carryproof-site-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.output = cls.root / "site"
        cls.hashes = build_site(cls.output)
        cls.document = (cls.output / "index.html").read_text(encoding="utf-8")

    def test_demo_and_downloaded_capsule_use_the_real_verifier(self) -> None:
        for name in ("index.html", "sample.carryproof.html"):
            result = cp.verify_capsule(self.output / name)
            self.assertTrue(result["ok"], result["failures"])
            self.assertEqual(result["checked"], 6)
        bundle = cp.verify_bundle(self.output / "sample.carryproof.zip")
        self.assertTrue(bundle["ok"], bundle["failures"])
        with zipfile.ZipFile(self.output / "carryproof.pyz") as archive:
            self.assertEqual(archive.namelist(), ["__main__.py"])
            self.assertEqual(
                archive.read("__main__.py"), build.SOURCE.read_text(encoding="utf-8").encode("utf-8")
            )

    def test_only_reviewed_public_artifacts_are_exported(self) -> None:
        self.assertEqual({path.name for path in self.output.iterdir()}, {
            "index.html", "report.html", "report.json", "sample.carryproof.html",
            "sample.carryproof.zip", "sample.carryproof.zip.cproof", "carryproof.pyz",
            "LICENSE.txt", "vercel.json", ".vercelignore", "404.html", "SHA256SUMS.txt",
        })
        report = json.loads((self.output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["original"]["summary"]["risk_score"], 75)
        self.assertEqual(report["prepared"]["summary"]["risk_score"], 5)
        self.assertEqual(report["prepared"]["summary"]["files"], 6)
        for section in report.values():
            self.assertNotIn("generated_utc", section)
            self.assertEqual(section["source"]["name"], "inbox")
        self.assertNotIn(str(self.root), self.document)
        self.assertNotIn("invoice.txt", self.document)
        self.assertNotIn("unsafe-archive.zip", self.document)
        publish_rules = (self.output / ".vercelignore").read_text(encoding="utf-8").splitlines()
        self.assertEqual(publish_rules[0], "*")
        self.assertNotIn("!.env.local", publish_rules)
        self.assertNotIn("!.vercel", publish_rules)
        for name in self.hashes:
            self.assertIn("!" + name, publish_rules)

    def test_page_has_five_replayable_steps_and_no_external_runtime_assets(self) -> None:
        tags = PageTags()
        tags.feed(self.document)
        steps = [attributes["data-step"] for _, attributes in tags.elements if "data-step" in attributes]
        self.assertEqual(steps, ["0", "1", "2", "3", "4"])
        ids = [attributes["id"] for _, attributes in tags.elements if "id" in attributes]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("openGuide", ids)
        self.assertIn("closeGuide", ids)
        self.assertIn("demoResources", ids)
        for tag, attributes in tags.elements:
            if tag == "script":
                self.assertNotIn("src", attributes)
            if tag == "link":
                self.assertNotEqual(attributes.get("rel"), "stylesheet")
        self.assertNotIn("fetch(", self.document)
        self.assertIn("connect-src 'none'", self.document)
        self.assertIn("synthetic JPEG/Office parser fixtures", self.document)
        self.assertIn("No login, access code, or upload is needed", self.document)

    def test_download_checksums_match_the_published_bytes(self) -> None:
        lines = (self.output / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines()
        self.assertEqual(len(lines), len(self.hashes))
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        self.assertEqual((self.output / "carryproof.pyz").read_bytes(), build.artifact_bytes())

    def test_public_demo_build_is_reproducible(self) -> None:
        other = self.root / "second"
        self.assertEqual(self.hashes, build_site(other))
        for path in self.output.iterdir():
            self.assertEqual(path.read_bytes(), (other / path.name).read_bytes(), path.name)

    def test_template_changes_fail_instead_of_silently_dropping_the_guide(self) -> None:
        self.assertEqual(insert_before("a</body>", "</body>", "b"), "ab</body>")
        with self.assertRaises(ValueError):
            insert_before("missing", "</body>", "b")
        with self.assertRaises(ValueError):
            insert_before("</body></body>", "</body>", "b")


if __name__ == "__main__":
    unittest.main()
