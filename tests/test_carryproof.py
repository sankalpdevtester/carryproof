from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import io
import json
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path
from unittest import mock

import carryproof as cp


def jpeg_fixture() -> bytes:
    tiff = bytearray(b"II\x2a\x00\x08\x00\x00\x00")
    tiff += b"\x02\x00"
    tiff += b"\x10\x01\x02\x00\x06\x00\x00\x00\x26\x00\x00\x00"
    tiff += b"\x25\x88\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00"
    tiff += b"\x00\x00\x00\x00Canon\x00"
    exif = b"Exif\x00\x00" + bytes(tiff)
    comment = b"created by Alice"
    return (
        b"\xff\xd8"
        + b"\xff\xe1"
        + (len(exif) + 2).to_bytes(2, "big")
        + exif
        + b"\xff\xfe"
        + (len(comment) + 2).to_bytes(2, "big")
        + comment
        + b"\xff\xda\x00\x02"
        + b"image-payload\xff\xd9"
    )


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind)
    crc = zlib.crc32(payload, crc) & 0xFFFFFFFF
    return len(payload).to_bytes(4, "big") + kind + payload + crc.to_bytes(4, "big")


def png_fixture() -> bytes:
    ihdr = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"tEXt", b"Author\x00Alice")
        + png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
        + png_chunk(b"IEND", b"")
    )


def office_fixture(path: Path) -> None:
    content_types = b'''<?xml version="1.0"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
      <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
    </Types>'''
    core = b'''<?xml version="1.0"?>
    <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:creator>Alice Example</dc:creator><cp:lastModifiedBy>Bob Example</cp:lastModifiedBy>
    </cp:coreProperties>'''
    relationships = b'''<?xml version="1.0"?>
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="rId1" Type="hyperlink" Target="https://tracker.invalid/pixel" TargetMode="External"/>
    </Relationships>'''
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("word/document.xml", b"<document>hello</document>")
        archive.writestr("docProps/core.xml", core)
        archive.writestr("word/_rels/document.xml.rels", relationships)
        archive.writestr("word/vbaProject.bin", b"macro")


class ParsingTests(unittest.TestCase):
    def test_parse_size(self) -> None:
        self.assertEqual(cp.parse_size("1 MiB"), 1024**2)
        self.assertEqual(cp.parse_size("2.5GB"), 2_500_000_000)

    def test_parse_duration(self) -> None:
        self.assertEqual(cp.parse_duration("1.5h"), 5400)
        self.assertEqual(cp.parse_duration("90"), 90)

    def test_archive_path_validation(self) -> None:
        self.assertTrue(cp.archive_name_is_unsafe("../escape"))
        self.assertTrue(cp.archive_name_is_unsafe("C:\\escape"))
        self.assertFalse(cp.archive_name_is_unsafe("folder/file.txt"))

    def test_http_ranges(self) -> None:
        self.assertEqual(cp.parse_http_range("bytes=10-19", 100), (10, 19))
        self.assertEqual(cp.parse_http_range("bytes=-10", 100), (90, 99))
        self.assertEqual(cp.parse_http_range("bytes=95-", 100), (95, 99))
        with self.assertRaises(cp.CarryProofError):
            cp.parse_http_range("bytes=100-101", 100)


class InspectionAndCleaningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="carryproof-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_jpeg_metadata_is_found_and_removed(self) -> None:
        source = self.root / "photo.jpg"
        source.write_bytes(jpeg_fixture())
        report = cp.inspect_target(source)
        codes = {item.code for item in report.findings}
        self.assertIn("privacy.image_metadata", codes)
        self.assertIn("GPS coordinates", report.files[0].metadata)
        cleaned = self.root / "clean.jpg"
        actions = cp.clean_jpeg(source, cleaned)
        self.assertTrue(any("EXIF" in action for action in actions))
        after = cp.inspect_target(cleaned)
        self.assertNotIn("privacy.image_metadata", {item.code for item in after.findings})
        self.assertIn(b"image-payload", cleaned.read_bytes())

    def test_png_metadata_is_found_and_removed(self) -> None:
        source = self.root / "image.png"
        source.write_bytes(png_fixture())
        report = cp.inspect_target(source)
        self.assertIn("privacy.image_metadata", {item.code for item in report.findings})
        cleaned = self.root / "clean.png"
        cp.clean_png(source, cleaned)
        self.assertNotIn(b"tEXt", cleaned.read_bytes())
        self.assertNotIn("privacy.image_metadata", {item.code for item in cp.inspect_target(cleaned).findings})

    def test_office_metadata_macros_and_links_are_removed(self) -> None:
        source = self.root / "brief.docm"
        office_fixture(source)
        report = cp.inspect_target(source)
        codes = {item.code for item in report.findings}
        self.assertIn("privacy.office_metadata", codes)
        self.assertIn("office.macros", codes)
        self.assertIn("office.external_links", codes)
        self.assertNotIn("file.extension_mismatch", codes)
        cleaned = self.root / "brief-clean.docm"
        cp.clean_office(source, cleaned, strip_active=True)
        with zipfile.ZipFile(cleaned) as archive:
            self.assertNotIn("word/vbaProject.bin", archive.namelist())
            self.assertNotIn(b"tracker.invalid", archive.read("word/_rels/document.xml.rels"))
            self.assertNotIn(b"Alice Example", archive.read("docProps/core.xml"))
            content_types = archive.read("[Content_Types].xml")
            self.assertIn(b"wordprocessingml.document.main+xml", content_types)
            self.assertNotIn(b"macroEnabled", content_types)
        after_codes = {item.code for item in cp.inspect_target(cleaned).findings}
        self.assertNotIn("office.macros", after_codes)
        self.assertNotIn("office.external_links", after_codes)
        self.assertNotIn("privacy.office_metadata", after_codes)

    def test_clean_workflow_renames_macro_enabled_office_output(self) -> None:
        source = self.root / "input"
        source.mkdir()
        office_fixture(source / "brief.docm")
        before = cp.inspect_target(source)
        output = self.root / "cleaned"
        cp.clean_target(source, output, before, strip_active=True)
        self.assertTrue((output / "brief.sanitized.docx").is_file())
        self.assertFalse((output / "brief.docm").exists())

    def test_sanitized_filename_collision_does_not_overwrite_a_copy(self) -> None:
        source = self.root / "input"
        source.mkdir()
        office_fixture(source / "brief.docm")
        (source / "brief.sanitized.docx").write_bytes(b"another original")
        before = cp.inspect_target(source)
        output = self.root / "cleaned"
        with self.assertRaisesRegex(cp.CarryProofError, "filename collision"):
            cp.clean_target(source, output, before, strip_active=True)
        with zipfile.ZipFile(output / "brief.sanitized.docx") as archive:
            self.assertEqual(archive.read("word/document.xml"), b"<document>hello</document>")
        self.assertEqual((source / "brief.sanitized.docx").read_bytes(), b"another original")

    def test_archive_traversal_and_bomb_ratio(self) -> None:
        source = self.root / "hostile.zip"
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../escape.txt", b"escape")
            archive.writestr("huge.txt", b"0" * (11 * 1024**2))
        report = cp.inspect_target(source)
        codes = {item.code for item in report.findings}
        self.assertIn("archive.path_traversal", codes)
        self.assertIn("archive.compression_ratio", codes)

    def test_standalone_gzip_is_not_reported_as_a_broken_tar(self) -> None:
        source = self.root / "message.txt.gz"
        with gzip.open(source, "wb") as handle:
            handle.write(b"standalone compressed text")
        report = cp.inspect_target(source)
        self.assertNotIn("archive.malformed", {item.code for item in report.findings})

    def test_content_scan_reports_counts_without_secret_values(self) -> None:
        secret = "AKIA" + "A" * 16
        source = self.root / "secrets.env"
        source.write_text(f"AWS_KEY={secret}\nEMAIL=alice@example.com\n", encoding="utf-8")
        report = cp.inspect_target(source, content_scan=True)
        serialized = json.dumps(report.as_dict())
        self.assertIn("content.aws_key", serialized)
        self.assertIn("content.email", serialized)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("alice@example.com", serialized)

    def test_malformed_json_gets_position(self) -> None:
        source = self.root / "broken.json"
        source.write_text('{"hello": }', encoding="utf-8")
        report = cp.inspect_target(source, content_scan=True)
        finding = next(item for item in report.findings if item.code == "data.invalid_json")
        self.assertIn("line 1", finding.detail)

    def test_duplicates_are_grouped(self) -> None:
        folder = self.root / "data"
        folder.mkdir()
        (folder / "one.txt").write_text("same", encoding="utf-8")
        (folder / "two.txt").write_text("same", encoding="utf-8")
        (folder / "three.txt").write_text("different", encoding="utf-8")
        report = cp.inspect_target(folder)
        self.assertEqual(len(report.duplicate_groups), 1)
        self.assertEqual(report.duplicate_groups[0]["reclaimable_bytes"], 4)

    def test_executable_disguised_as_text_is_critical(self) -> None:
        source = self.root / "invoice.txt"
        source.write_bytes(b"MZ" + b"\x00" * 100)
        report = cp.inspect_target(source)
        finding = next(item for item in report.findings if item.code == "file.extension_mismatch")
        self.assertEqual(finding.severity, "critical")


class ProtectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="carryproof-protect-")
        self.root = Path(self.temp.name)
        self.original = self.root / "original.bin"
        self.original.write_bytes(bytes(range(251)) * 1000)
        self.parity = self.root / "original.cproof"
        cp.create_parity(self.original, self.parity, chunk_size=4096, stripe_width=4)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_clean_file_verifies_without_repair(self) -> None:
        output = self.root / "verified.bin"
        result = cp.recover_with_parity(self.original, self.parity, output)
        self.assertEqual(result["repaired_chunks"], 0)
        self.assertEqual(output.read_bytes(), self.original.read_bytes())

    def test_one_bad_chunk_is_repaired(self) -> None:
        data = bytearray(self.original.read_bytes())
        data[5000:5500] = b"x" * 500
        damaged = self.root / "damaged.bin"
        damaged.write_bytes(data)
        output = self.root / "recovered.bin"
        result = cp.recover_with_parity(damaged, self.parity, output)
        self.assertEqual(result["repaired_chunks"], 1)
        self.assertEqual(output.read_bytes(), self.original.read_bytes())

    def test_two_bad_chunks_in_one_stripe_fail_safely(self) -> None:
        data = bytearray(self.original.read_bytes())
        data[10:20] = b"x" * 10
        data[5000:5010] = b"y" * 10
        damaged = self.root / "damaged.bin"
        damaged.write_bytes(data)
        output = self.root / "should-not-exist.bin"
        with self.assertRaises(cp.CarryProofError):
            cp.recover_with_parity(damaged, self.parity, output)
        self.assertFalse(output.exists())


class BundleAndWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="carryproof-bundle-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_bundle_build_is_byte_reproducible_and_verifiable(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "a.txt").write_text("alpha", encoding="utf-8")
        (source / "b.txt").write_text("beta", encoding="utf-8")
        report = cp.inspect_target(source)
        first = self.root / "one.zip"
        second = self.root / "two.zip"
        cp.make_bundle(source, first, report)
        cp.make_bundle(source, second, report)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        result = cp.verify_bundle(first)
        self.assertTrue(result["ok"])
        self.assertEqual(result["checked"], 2)

    def test_bundle_rejects_incomplete_or_mismatched_inventory(self) -> None:
        payload = b"ordinary data"
        entry = {"path": "note.txt", "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        valid = {"schema": 1, "tool": "CarryProof", "files": [entry]}
        cases = (
            ({}, {"note.txt": payload}),
            ({**valid, "files": []}, {"note.txt": payload}),
            (valid, {}),
            (valid, {"note.txt": payload, "extra.txt": b"unexpected"}),
            ({**valid, "files": [entry, entry]}, {"note.txt": payload}),
            ({**valid, "files": [{**entry, "size": 999}]}, {"note.txt": payload}),
            (valid, {"note.txt": b"modified"}),
        )
        for index, (manifest, files) in enumerate(cases):
            with self.subTest(index=index):
                bundle = self.root / f"invalid-{index}.zip"
                with zipfile.ZipFile(bundle, "w") as archive:
                    archive.writestr("CARRYPROOF-MANIFEST.json", json.dumps(manifest))
                    for name, data in files.items():
                        archive.writestr(name, data)
                self.assertFalse(cp.verify_bundle(bundle)["ok"])

    def test_bundle_rejects_reserved_metadata_filenames(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "CARRYPROOF-MANIFEST.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(cp.CarryProofError, "reserved bundle metadata"):
            cp.make_bundle(source, self.root / "invalid.zip", cp.inspect_target(source))
        self.assertFalse((self.root / "invalid.zip").exists())

    def test_bundle_verifier_applies_expanded_size_limit(self) -> None:
        bundle = self.root / "oversize.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("CARRYPROOF-MANIFEST.json", "{}")
        with mock.patch.object(cp, "ScanLimits", return_value=cp.ScanLimits(max_archive_expanded=1)):
            result = cp.verify_bundle(bundle)
        self.assertFalse(result["ok"])
        self.assertIn("size exceeds", result["failures"][0])

    def test_report_html_escapes_script_boundaries(self) -> None:
        report = cp.Report("<script>alert(1)</script>", "file", False)
        output = cp.generate_report_html(report).decode("utf-8")
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertIn("\\u003cscript", output)

    def test_complete_prepare_workflow(self) -> None:
        source = self.root / "input"
        source.mkdir()
        (source / "photo.jpg").write_bytes(jpeg_fixture())
        (source / "note.txt").write_text("hello", encoding="utf-8")
        output = self.root / "prepared"
        result = cp.prepare_workflow(
            source,
            output,
            overwrite=False,
            content_scan=True,
            strip_active=True,
            parity=True,
            chunk_size=4096,
            stripe_width=4,
        )
        self.assertTrue(Path(result["bundle"]).is_file())
        self.assertTrue(Path(result["parity"]).is_file())
        self.assertTrue(Path(result["capsule"]).is_file())
        self.assertTrue((output / "carryproof-report.html").is_file())
        self.assertTrue(cp.verify_bundle(Path(result["bundle"]))["ok"])
        self.assertTrue(cp.verify_capsule(Path(result["capsule"]))["ok"])
        with zipfile.ZipFile(result["bundle"]) as archive:
            document = archive.read("CARRYPROOF-REPORT.html").decode("utf-8")
        report_data = json.loads(re.search(
            r'id="report-data" type="application/json">(.*?)</script>', document, re.DOTALL
        ).group(1))
        self.assertNotIn("generated_utc", report_data["original"])
        self.assertNotIn("generated_utc", report_data["prepared"])
        self.assertNotIn("privacy.image_metadata", {item.code for item in result["prepared"].findings})

    def test_capsule_is_reproducible_and_every_payload_is_verifiable(self) -> None:
        source = self.root / "handoff"
        source.mkdir()
        (source / "alpha.txt").write_text("alpha", encoding="utf-8")
        (source / "photo.jpg").write_bytes(jpeg_fixture())
        results = []
        for name in ("prepared-one", "prepared-two"):
            results.append(
                cp.prepare_workflow(
                    source,
                    self.root / name,
                    overwrite=False,
                    content_scan=True,
                    strip_active=True,
                    parity=False,
                    chunk_size=4096,
                    stripe_width=4,
                )
            )
        first = Path(results[0]["capsule"])
        second = Path(results[1]["capsule"])
        self.assertEqual(first.read_bytes(), second.read_bytes())
        document = first.read_text(encoding="utf-8")
        manifest_text = re.search(
            r'id="capsule-manifest" type="application/json">(.*?)</script>', document, re.DOTALL
        ).group(1)
        payload_text = re.search(
            r'id="capsule-files" type="application/json">(.*?)</script>', document, re.DOTALL
        ).group(1)
        seal = re.search(r'<meta name="capsule-seal" content="([0-9a-f]{64})">', document).group(1)
        manifest = json.loads(manifest_text)
        payloads = json.loads(payload_text)
        self.assertEqual(hashlib.sha256(manifest_text.encode()).hexdigest(), seal)
        self.assertEqual(len(payloads), len(manifest["files"]))
        for metadata, payload in zip(manifest["files"], payloads, strict=True):
            decoded = base64.b64decode(payload["data"], validate=True)
            self.assertEqual(payload["path"], metadata["path"])
            self.assertEqual(len(decoded), metadata["size"])
            self.assertEqual(hashlib.sha256(decoded).hexdigest(), metadata["sha256"])
        tampered = bytearray(base64.b64decode(payloads[0]["data"], validate=True))
        tampered[0] ^= 0x01
        self.assertNotEqual(hashlib.sha256(tampered).hexdigest(), manifest["files"][0]["sha256"])

    def test_capsule_refuses_a_file_changed_after_inspection(self) -> None:
        source = self.root / "changing"
        source.mkdir()
        item = source / "note.txt"
        item.write_text("before", encoding="utf-8")
        original = cp.inspect_target(source)
        original.files[0].prepared_path = "note.txt"
        original.files[0].cleaning = ["copied unchanged"]
        prepared = cp.inspect_target(source)
        item.write_text("after", encoding="utf-8")
        with self.assertRaises(cp.CarryProofError):
            cp.create_capsule(source, self.root / "invalid.carryproof.html", original, prepared)
        self.assertFalse((self.root / "invalid.carryproof.html").exists())


class CapsuleVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="carryproof-capsule-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "note.txt").write_bytes(b"ordinary fixture")
        self.before = cp.inspect_target(self.source)
        self.after = cp.inspect_target(self.source)
        self.capsule = self.root / "source.carryproof.html"
        self.result = cp.create_capsule(self.source, self.capsule, self.before, self.after)
        self.document = self.capsule.read_bytes().decode("utf-8")
        parser = cp.CapsuleDataParser()
        parser.feed(self.document)
        parser.close()
        self.manifest_text = "".join(parser.islands["capsule-manifest"])
        self.payload_text = "".join(parser.islands["capsule-files"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def altered(self, document: str) -> Path:
        target = self.root / "altered.html"
        target.write_bytes(document.encode("utf-8"))
        return target

    def test_valid_capsule_and_trusted_whole_file_hash(self) -> None:
        result = cp.verify_capsule(self.capsule, self.result["sha256"])
        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["checked"], 1)
        self.assertTrue(result["trusted_hash_checked"])
        self.assertFalse(cp.verify_capsule(self.capsule, "0" * 64)["ok"])

    def test_payload_tampering_fails_product_verifier_and_cli(self) -> None:
        payloads = json.loads(self.payload_text)
        data = bytearray(base64.b64decode(payloads[0]["data"]))
        data[0] ^= 1
        payloads[0]["data"] = base64.b64encode(data).decode("ascii")
        changed = self.altered(self.document.replace(self.payload_text, json.dumps(payloads)))
        result = cp.verify_capsule(changed)
        self.assertFalse(result["ok"])
        self.assertIn("mismatch", result["failures"][0])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cp.main(["verify", str(changed)]), 4)

    def test_manifest_tampering_fails_seal_check(self) -> None:
        changed_text = self.manifest_text.replace('"source_name":"source"', '"source_name":"forged"')
        changed = self.altered(self.document.replace(self.manifest_text, changed_text))
        result = cp.verify_capsule(changed)
        self.assertFalse(result["ok"])
        self.assertIn("Manifest seal mismatch", result["failures"])

    def test_missing_extra_and_invalid_base64_payloads_fail(self) -> None:
        payloads = json.loads(self.payload_text)
        invalid = [{"path": "note.txt", "data": "not base64!"}]
        for value in ([], payloads + payloads, invalid):
            with self.subTest(value=value):
                changed = self.altered(self.document.replace(self.payload_text, json.dumps(value)))
                self.assertFalse(cp.verify_capsule(changed)["ok"])

    def test_duplicate_data_island_is_rejected(self) -> None:
        duplicate = '<script id="capsule-manifest" type="application/json">{}</script>'
        changed = self.altered(self.document + duplicate)
        self.assertFalse(cp.verify_capsule(changed)["ok"])

    def test_whole_file_hash_detects_changed_verifier_code(self) -> None:
        changed = self.altered(self.document.replace("const $ = id =>", "throw new Error('do not execute'); const $ = id =>"))
        self.assertTrue(cp.verify_capsule(changed)["ok"])
        result = cp.verify_capsule(changed, self.result["sha256"])
        self.assertFalse(result["ok"])
        self.assertIn("Whole-capsule", result["failures"][0])

    def test_post_scan_inventory_changes_are_rejected(self) -> None:
        extra = self.source / "unscanned.txt"
        extra.write_text("new content", encoding="utf-8")
        with self.assertRaises(cp.CarryProofError):
            cp.create_capsule(self.source, self.root / "unexpected.html", self.before, self.after)
        extra.unlink()
        (self.source / "note.txt").unlink()
        with self.assertRaises(cp.CarryProofError):
            cp.create_capsule(self.source, self.root / "unexpected.html", self.before, self.after)
        self.assertFalse((self.root / "unexpected.html").exists())

    def test_streaming_base64_across_block_boundaries(self) -> None:
        item = self.source / "note.txt"
        item.write_bytes(bytes(range(256)) * (cp.CAPSULE_BUFFER // 256 + 1) + b"xy")
        report = cp.inspect_target(self.source)
        cp.create_capsule(self.source, self.capsule, report, report)
        result = cp.verify_capsule(self.capsule)
        self.assertTrue(result["ok"], result["failures"])

    def test_verifier_enforces_input_size_limit(self) -> None:
        with mock.patch.object(cp, "MAX_CAPSULE_VERIFY_BYTES", 8):
            result = cp.verify_capsule(self.capsule)
        self.assertFalse(result["ok"])
        self.assertIn("limit", result["failures"][0])

    def test_report_timestamps_do_not_change_embedded_bundle_bytes(self) -> None:
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        html = cp.generate_report_html(self.before, self.after, include_generated=False)
        cp.make_bundle(self.source, first, self.before, html, after=self.after)
        self.before.generated_utc = "2099-01-01T00:00:00Z"
        self.after.generated_utc = "2099-01-02T00:00:00Z"
        html = cp.generate_report_html(self.before, self.after, include_generated=False)
        cp.make_bundle(self.source, second, self.before, html, after=self.after)
        self.assertEqual(first.read_bytes(), second.read_bytes())


class PortalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="carryproof-portal-")
        self.root = Path(self.temp.name)
        (self.root / "hello.txt").write_text("hello portal", encoding="utf-8")
        self.state = cp.PortalState(self.root, "12345678")
        self.server = cp.CarryProofServer(("127.0.0.1", 0), self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def login_cookie(self) -> str:
        request = urllib.request.Request(
            self.base + "/api/login",
            data=json.dumps({"code": "1234-5678"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.headers["Set-Cookie"].split(";", 1)[0]

    def test_auth_list_and_range_download(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(self.base + "/api/info", timeout=3)
        self.assertEqual(caught.exception.code, 401)
        cookie = self.login_cookie()
        list_request = urllib.request.Request(self.base + "/api/list", headers={"Cookie": cookie})
        with urllib.request.urlopen(list_request, timeout=3) as response:
            listing = json.load(response)
        self.assertEqual(listing["entries"][0]["name"], "hello.txt")
        file_request = urllib.request.Request(
            self.base + "/file?path=hello.txt",
            headers={"Cookie": cookie, "Range": "bytes=6-11"},
        )
        with urllib.request.urlopen(file_request, timeout=3) as response:
            self.assertEqual(response.status, 206)
            self.assertEqual(response.read(), b"portal")

    def test_portal_blocks_path_traversal(self) -> None:
        with self.assertRaises(cp.CarryProofError):
            self.state.resolve("../outside.txt")

    def test_demo_code_is_disclosed_only_in_demo_mode(self) -> None:
        with urllib.request.urlopen(self.base + "/", timeout=3) as response:
            ordinary = response.read()
        self.assertNotIn(b"12345678", ordinary)
        self.state.demo = True
        with urllib.request.urlopen(self.base + "/", timeout=3) as response:
            demo = response.read()
        self.assertIn(b"12345678", demo)
        self.assertIn(b"Judge demo code", demo)

    def test_report_and_capsule_routes_apply_path_confinement(self) -> None:
        (self.root / "example.carryproof.html").write_text("fixture", encoding="utf-8")
        with mock.patch.object(self.state, "resolve", side_effect=cp.CarryProofError("Outside root")):
            self.assertIsNone(self.state.report_path("carryproof-report.html"))
            self.assertIsNone(self.state.capsule_path())


if __name__ == "__main__":
    unittest.main()
