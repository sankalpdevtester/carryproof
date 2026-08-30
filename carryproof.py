#!/usr/bin/env python3
"""CarryProof: inspect, prepare, and verify file handoffs."""

from __future__ import annotations

import argparse
import base64
import bz2
import contextlib
import csv
import datetime as dt
import hashlib
import hmac
import gzip
import io
import json
import lzma
import mimetypes
import os
import re
import secrets
import shutil
import socket
import stat
import struct
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
import zlib
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http import HTTPStatus, cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator
from xml.etree import ElementTree as ET


APP_NAME = "CarryProof"
VERSION = "2.0.0"
REPORT_SCHEMA = 1
PARITY_MAGIC = b"CPRF1\x00"
COPY_BUFFER = 1024 * 1024
CAPSULE_BUFFER = 3 * 256 * 1024
MAX_CAPSULE_VERIFY_BYTES = 128 * 1024**2
BUNDLE_METADATA = frozenset({"CARRYPROOF-MANIFEST.json", "CARRYPROOF-REPORT.json", "CARRYPROOF-REPORT.html"})
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_WEIGHTS = {"info": 0, "low": 1, "medium": 4, "high": 12, "critical": 30}


class CarryProofError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    location: str
    message: str
    detail: str = ""
    remediation: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "location": self.location,
            "message": self.message,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class FileRecord:
    path: str
    size: int
    sha256: str
    detected_type: str
    extension: str
    mime: str
    metadata: list[str] = field(default_factory=list)
    duplicate_of: str | None = None
    cleaning: list[str] = field(default_factory=list)
    prepared_path: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "type": self.detected_type,
            "extension": self.extension,
            "mime": self.mime,
            "metadata": sorted(set(self.metadata)),
        }
        if self.duplicate_of:
            result["duplicate_of"] = self.duplicate_of
        if self.cleaning:
            result["cleaning"] = self.cleaning
        if self.prepared_path:
            result["prepared_path"] = self.prepared_path
        return result


@dataclass(frozen=True)
class ScanLimits:
    max_files: int = 100_000
    max_archive_members: int = 20_000
    max_archive_expanded: int = 2 * 1024**3
    max_nested_member: int = 32 * 1024**2
    max_nested_depth: int = 2
    max_text_scan: int = 4 * 1024**2


@dataclass
class Report:
    source_name: str
    source_kind: str
    content_scan: bool
    files: list[FileRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    duplicate_groups: list[dict[str, Any]] = field(default_factory=list)
    generated_utc: str = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    def add(
        self,
        severity: str,
        code: str,
        location: str,
        message: str,
        detail: str = "",
        remediation: str = "",
    ) -> None:
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"Unknown severity: {severity}")
        self.findings.append(
            Finding(severity, code, location, message, detail, remediation)
        )

    @property
    def risk_score(self) -> int:
        raw = sum(RISK_WEIGHTS[item.severity] for item in self.findings)
        return min(100, raw)

    @property
    def status(self) -> str:
        if any(item.severity == "critical" for item in self.findings):
            return "blocked"
        if any(item.severity == "high" for item in self.findings):
            return "review"
        if any(item.severity == "medium" for item in self.findings):
            return "caution"
        return "clear"

    def summary(self) -> dict[str, Any]:
        severities = Counter(item.severity for item in self.findings)
        total_bytes = sum(item.size for item in self.files)
        duplicate_bytes = sum(group["reclaimable_bytes"] for group in self.duplicate_groups)
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "files": len(self.files),
            "bytes": total_bytes,
            "findings": len(self.findings),
            "severity_counts": {
                name: severities.get(name, 0)
                for name in ("critical", "high", "medium", "low", "info")
            },
            "duplicate_groups": len(self.duplicate_groups),
            "reclaimable_bytes": duplicate_bytes,
        }

    def as_dict(self, include_generated: bool = True) -> dict[str, Any]:
        findings = sorted(
            self.findings,
            key=lambda item: (-SEVERITY_ORDER[item.severity], item.location, item.code),
        )
        result: dict[str, Any] = {
            "schema": REPORT_SCHEMA,
            "tool": APP_NAME,
            "version": VERSION,
            "source": {"name": self.source_name, "kind": self.source_kind},
            "content_scan": self.content_scan,
            "summary": self.summary(),
            "findings": [item.as_dict() for item in findings],
            "files": [item.as_dict() for item in sorted(self.files, key=lambda x: x.path)],
            "duplicates": self.duplicate_groups,
        }
        if include_generated:
            result["generated_utc"] = self.generated_utc
        return result


def human_size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


def parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)?\s*", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError(f"Invalid size: {value}")
    amount = float(match.group(1))
    suffix = (match.group(2) or "b").lower()
    multipliers = {
        "": 1,
        "b": 1,
        "k": 1000,
        "kb": 1000,
        "ki": 1024,
        "kib": 1024,
        "m": 1000**2,
        "mb": 1000**2,
        "mi": 1024**2,
        "mib": 1024**2,
        "g": 1000**3,
        "gb": 1000**3,
        "gi": 1024**3,
        "gib": 1024**3,
        "t": 1000**4,
        "tb": 1000**4,
        "ti": 1024**4,
        "tib": 1024**4,
    }
    return int(amount * multipliers[suffix])


def parse_duration(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError(f"Invalid duration: {value}")
    amount = float(match.group(1))
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[
        match.group(2).lower()
    ]
    return int(amount * multiplier)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(COPY_BUFFER), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_stream(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    for block in iter(lambda: handle.read(COPY_BUFFER), b""):
        digest.update(block)
    return digest.hexdigest()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def archive_name_is_unsafe(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if not normalized or "\x00" in normalized:
        return True
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return True
    return any(part == ".." for part in PurePosixPath(normalized).parts)


def safe_relative_path(value: str) -> PurePosixPath:
    value = value.replace("\\", "/")
    if archive_name_is_unsafe(value):
        raise CarryProofError(f"Unsafe relative path: {value}")
    parts = [part for part in PurePosixPath(value).parts if part not in ("", ".")]
    if not parts:
        raise CarryProofError("Path cannot be empty")
    return PurePosixPath(*parts)


def is_probably_text(head: bytes) -> bool:
    if b"\x00" in head:
        return False
    if not head:
        return True
    sample = head[:4096]
    control = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control / len(sample) < 0.02


MAGIC_EXTENSIONS: dict[str, set[str]] = {
    "jpeg": {".jpg", ".jpeg", ".jpe"},
    "png": {".png"},
    "gif": {".gif"},
    "pdf": {".pdf"},
    "zip": {
        ".zip",
        ".jar",
        ".apk",
        ".epub",
        ".docx",
        ".docm",
        ".xlsx",
        ".xlsm",
        ".pptx",
        ".pptm",
    },
    "gzip": {".gz", ".tgz"},
    "bzip2": {".bz2", ".tbz", ".tbz2"},
    "xz": {".xz", ".txz"},
    "tar": {".tar"},
    "rar": {".rar"},
    "7z": {".7z"},
    "pe-executable": {".exe", ".dll", ".sys", ".scr", ".com"},
    "elf-executable": {"", ".so", ".bin", ".run"},
    "sqlite": {".db", ".sqlite", ".sqlite3"},
}


def detect_type(path: Path, head: bytes | None = None) -> str:
    if head is None:
        with path.open("rb") as handle:
            head = handle.read(1024)
    assert head is not None
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if len(head) > 265 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if head.startswith(b"MZ"):
        return "pe-executable"
    if head.startswith(b"\x7fELF"):
        return "elf-executable"
    if head.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")):
        return "mach-o-executable"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    suffix = path.suffix.lower()
    if stripped.startswith((b"<?xml", b"<svg")):
        return "svg" if suffix == ".svg" or b"<svg" in stripped[:512].lower() else "xml"
    if stripped.startswith((b"<!doctype html", b"<html")):
        return "html"
    if suffix == ".json":
        return "json"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    if suffix in {".txt", ".md", ".markdown", ".log", ".ini", ".toml", ".yaml", ".yml", ".env"}:
        return "text"
    return "text" if is_probably_text(head) else "binary"


EXIF_TAGS = {
    0x010E: "image description",
    0x010F: "camera make",
    0x0110: "camera model",
    0x0131: "editing software",
    0x0132: "capture timestamp",
    0x013B: "artist",
    0x8298: "copyright",
    0x9286: "user comment",
    0xA420: "image unique ID",
    0xA430: "camera owner",
    0xA431: "camera serial number",
    0xA435: "lens serial number",
}


def exif_metadata_names(payload: bytes) -> set[str]:
    if not payload.startswith(b"Exif\x00\x00"):
        return set()
    data = payload[6:]
    if len(data) < 8 or data[:2] not in (b"II", b"MM"):
        return {"EXIF metadata"}
    endian = "<" if data[:2] == b"II" else ">"

    def u16(offset: int) -> int:
        if offset < 0 or offset + 2 > len(data):
            raise ValueError
        return struct.unpack_from(endian + "H", data, offset)[0]

    def u32(offset: int) -> int:
        if offset < 0 or offset + 4 > len(data):
            raise ValueError
        return struct.unpack_from(endian + "I", data, offset)[0]

    names: set[str] = set()
    visited: set[int] = set()

    def parse_ifd(offset: int, label: str, depth: int = 0) -> None:
        if depth > 4 or offset in visited or offset + 2 > len(data):
            return
        visited.add(offset)
        count = min(u16(offset), 2048)
        for index in range(count):
            item = offset + 2 + index * 12
            if item + 12 > len(data):
                break
            tag = u16(item)
            value_or_offset = u32(item + 8)
            if label == "gps":
                names.add("GPS coordinates")
            if tag in EXIF_TAGS:
                names.add(EXIF_TAGS[tag])
            if tag == 0x8769:
                names.add("EXIF camera metadata")
                parse_ifd(value_or_offset, "exif", depth + 1)
            elif tag == 0x8825:
                names.add("GPS coordinates")
                parse_ifd(value_or_offset, "gps", depth + 1)

    try:
        if u16(2) != 42:
            return {"EXIF metadata"}
        parse_ifd(u32(4), "primary")
    except (ValueError, struct.error):
        return {"EXIF metadata (malformed)"}
    return names or {"EXIF metadata"}


def iter_jpeg_header(handle: BinaryIO) -> Iterator[tuple[int, bytes]]:
    if handle.read(2) != b"\xff\xd8":
        raise CarryProofError("Invalid JPEG signature")
    while True:
        prefix = handle.read(1)
        if not prefix:
            return
        while prefix != b"\xff":
            prefix = handle.read(1)
            if not prefix:
                return
        marker_byte = handle.read(1)
        while marker_byte == b"\xff":
            marker_byte = handle.read(1)
        if not marker_byte:
            return
        marker = marker_byte[0]
        if marker == 0xDA:
            length_data = handle.read(2)
            if len(length_data) != 2:
                raise CarryProofError("Truncated JPEG scan header")
            length = struct.unpack(">H", length_data)[0]
            payload = handle.read(length - 2)
            if len(payload) != length - 2:
                raise CarryProofError("Truncated JPEG scan header")
            yield marker, payload
            return
        if marker in {0xD8, 0xD9, 0x01} or 0xD0 <= marker <= 0xD7:
            yield marker, b""
            if marker == 0xD9:
                return
            continue
        length_data = handle.read(2)
        if len(length_data) != 2:
            raise CarryProofError("Truncated JPEG segment")
        length = struct.unpack(">H", length_data)[0]
        if length < 2:
            raise CarryProofError("Invalid JPEG segment length")
        payload = handle.read(length - 2)
        if len(payload) != length - 2:
            raise CarryProofError("Truncated JPEG segment")
        yield marker, payload


def inspect_jpeg(path: Path, location: str, report: Report) -> list[str]:
    metadata: set[str] = set()
    try:
        with path.open("rb") as handle:
            for marker, payload in iter_jpeg_header(handle):
                if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                    metadata.update(exif_metadata_names(payload))
                elif marker == 0xE1 and b"xap/1.0" in payload[:128]:
                    metadata.add("XMP metadata")
                elif marker == 0xED:
                    metadata.add("IPTC/Photoshop metadata")
                elif marker == 0xFE:
                    metadata.add("JPEG comment")
    except (OSError, CarryProofError) as exc:
        report.add("medium", "jpeg.malformed", location, "JPEG metadata could not be parsed", str(exc))
    if metadata:
        severity = "high" if "GPS coordinates" in metadata else "medium"
        report.add(
            severity,
            "privacy.image_metadata",
            location,
            "Image contains shareable metadata",
            ", ".join(sorted(metadata)),
            "Create a sanitized copy before sharing.",
        )
    return sorted(metadata)


PNG_METADATA_CHUNKS = {
    b"tEXt": "PNG text metadata",
    b"zTXt": "compressed PNG text metadata",
    b"iTXt": "international PNG text/XMP metadata",
    b"eXIf": "EXIF metadata",
    b"tIME": "image modification timestamp",
}


def iter_png_chunks(handle: BinaryIO) -> Iterator[tuple[bytes, bytes, bytes]]:
    if handle.read(8) != b"\x89PNG\r\n\x1a\n":
        raise CarryProofError("Invalid PNG signature")
    while True:
        header = handle.read(8)
        if not header:
            return
        if len(header) != 8:
            raise CarryProofError("Truncated PNG chunk header")
        length, kind = struct.unpack(">I4s", header)
        if length > 512 * 1024**2:
            raise CarryProofError("Unreasonable PNG chunk length")
        payload = handle.read(length)
        crc = handle.read(4)
        if len(payload) != length or len(crc) != 4:
            raise CarryProofError("Truncated PNG chunk")
        expected = zlib.crc32(kind)
        expected = zlib.crc32(payload, expected) & 0xFFFFFFFF
        actual = struct.unpack(">I", crc)[0]
        if expected != actual:
            raise CarryProofError(f"PNG chunk {kind.decode('ascii', 'replace')} has a bad CRC")
        yield kind, payload, crc
        if kind == b"IEND":
            return


def inspect_png(path: Path, location: str, report: Report) -> list[str]:
    metadata: set[str] = set()
    try:
        with path.open("rb") as handle:
            for kind, _payload, _crc in iter_png_chunks(handle):
                if kind in PNG_METADATA_CHUNKS:
                    metadata.add(PNG_METADATA_CHUNKS[kind])
    except (OSError, CarryProofError) as exc:
        report.add("medium", "png.malformed", location, "PNG structure could not be validated", str(exc))
    if metadata:
        report.add(
            "medium",
            "privacy.image_metadata",
            location,
            "PNG contains removable metadata",
            ", ".join(sorted(metadata)),
            "Create a sanitized copy before sharing.",
        )
    return sorted(metadata)


def read_limited(handle: BinaryIO, limit: int) -> bytes:
    data = handle.read(limit + 1)
    if len(data) > limit:
        raise CarryProofError(f"Input exceeds inspection limit of {human_size(limit)}")
    return data


def zip_kind(archive: zipfile.ZipFile) -> str:
    names = {name.lower() for name in archive.namelist()}
    if "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    if "ppt/presentation.xml" in names:
        return "pptx"
    if "meta-inf/container.xml" in names and "mimetype" in names:
        return "epub"
    return "zip"


OFFICE_PRIVATE_PROPERTIES = {
    "creator": "document author",
    "lastModifiedBy": "last editor",
    "created": "creation timestamp",
    "modified": "modification timestamp",
    "lastPrinted": "last printed timestamp",
    "revision": "revision number",
    "Manager": "manager",
    "Company": "company",
    "Template": "template path",
    "HyperlinkBase": "hyperlink base path",
    "Application": "creating application",
    "AppVersion": "application version",
}


def inspect_office_metadata(
    archive: zipfile.ZipFile, location: str, report: Report
) -> list[str]:
    metadata: set[str] = set()
    for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
        try:
            info = archive.getinfo(name)
        except KeyError:
            continue
        if info.file_size > 2 * 1024**2:
            report.add("medium", "office.metadata_large", f"{location}!{name}", "Office metadata part is unexpectedly large")
            continue
        try:
            root = ET.fromstring(archive.read(info))
        except (ET.ParseError, RuntimeError, zipfile.BadZipFile):
            report.add("medium", "office.metadata_malformed", f"{location}!{name}", "Office metadata XML is malformed")
            continue
        if name.endswith("custom.xml") and list(root):
            metadata.add("custom document properties")
        for element in root.iter():
            key = local_name(element.tag)
            if key in OFFICE_PRIVATE_PROPERTIES and (element.text or "").strip():
                metadata.add(OFFICE_PRIVATE_PROPERTIES[key])
    if metadata:
        report.add(
            "high" if {"document author", "last editor"} & metadata else "medium",
            "privacy.office_metadata",
            location,
            "Office document exposes authorship or history metadata",
            ", ".join(sorted(metadata)),
            "Create a sanitized Office copy before sharing.",
        )
    return sorted(metadata)


def inspect_office_active_content(
    archive: zipfile.ZipFile, location: str, report: Report
) -> None:
    names = [name.replace("\\", "/") for name in archive.namelist()]
    lowered = [name.lower() for name in names]
    macro_parts = [name for name, low in zip(names, lowered) if "vbaproject.bin" in low or "/macros/" in low]
    embedded = [name for name, low in zip(names, lowered) if "/embeddings/" in low or "/activex/" in low]
    if macro_parts:
        report.add(
            "critical",
            "office.macros",
            location,
            "Office document contains executable macros",
            ", ".join(macro_parts[:8]),
            "Remove macros unless they are expected and trusted.",
        )
    if embedded:
        report.add(
            "high",
            "office.embedded_objects",
            location,
            "Office document contains embedded or active objects",
            ", ".join(embedded[:8]),
            "Review or remove embedded objects before sharing.",
        )
    external: list[str] = []
    for name in names:
        if not name.lower().endswith(".rels"):
            continue
        try:
            info = archive.getinfo(name)
            if info.file_size > 2 * 1024**2:
                continue
            root = ET.fromstring(archive.read(info))
            for relation in root.iter():
                if local_name(relation.tag) != "Relationship":
                    continue
                if relation.attrib.get("TargetMode", "").lower() == "external":
                    target = relation.attrib.get("Target", "")
                    external.append(f"{name}: {target[:120]}")
        except (ET.ParseError, KeyError, RuntimeError, zipfile.BadZipFile):
            continue
    if external:
        report.add(
            "high",
            "office.external_links",
            location,
            "Office document can contact external locations",
            "; ".join(external[:8]),
            "Strip active content or review every external relationship.",
        )


def inspect_zip(
    source: Path | bytes,
    location: str,
    report: Report,
    limits: ScanLimits,
    depth: int = 0,
) -> tuple[str, list[str]]:
    metadata: list[str] = []
    try:
        holder: Path | io.BytesIO
        holder = source if isinstance(source, Path) else io.BytesIO(source)
        with zipfile.ZipFile(holder) as archive:
            kind = zip_kind(archive)
            infos = archive.infolist()
            if len(infos) > limits.max_archive_members:
                report.add(
                    "critical",
                    "archive.member_count",
                    location,
                    "Archive contains an excessive number of entries",
                    f"{len(infos):,} entries; limit {limits.max_archive_members:,}",
                )
            total_uncompressed = 0
            total_compressed = 0
            nested: list[zipfile.ZipInfo] = []
            for info in infos[: limits.max_archive_members + 1]:
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
                member_location = f"{location}!{info.filename}"
                if archive_name_is_unsafe(info.filename):
                    report.add(
                        "critical",
                        "archive.path_traversal",
                        member_location,
                        "Archive entry can escape the extraction directory",
                        remediation="Do not extract this archive with a general-purpose tool.",
                    )
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    report.add(
                        "high",
                        "archive.symlink",
                        member_location,
                        "Archive contains a symbolic link",
                        remediation="Inspect the link target before extraction.",
                    )
                if info.flag_bits & 0x1:
                    report.add("medium", "archive.encrypted", member_location, "Encrypted archive entry cannot be inspected")
                if info.compress_size == 0 and info.file_size > 1024**2:
                    report.add("critical", "archive.zero_compressed", member_location, "Archive entry has suspicious expansion characteristics")
                elif info.compress_size and info.file_size > 10 * 1024**2:
                    ratio = info.file_size / info.compress_size
                    if ratio > 150:
                        report.add(
                            "high",
                            "archive.compression_ratio",
                            member_location,
                            "Archive entry has a zip-bomb-like compression ratio",
                            f"{ratio:.1f}:1 expands to {human_size(info.file_size)}",
                        )
                low = info.filename.lower()
                if low.endswith((".zip", ".jar", ".apk", ".epub")) and not info.is_dir():
                    nested.append(info)
            if total_uncompressed > limits.max_archive_expanded:
                report.add(
                    "critical",
                    "archive.expanded_size",
                    location,
                    "Archive expands beyond the configured safety limit",
                    f"{human_size(total_uncompressed)} expanded; limit {human_size(limits.max_archive_expanded)}",
                )
            if total_compressed and total_uncompressed > 50 * 1024**2:
                ratio = total_uncompressed / total_compressed
                if ratio > 100:
                    report.add("high", "archive.total_ratio", location, "Archive has a suspicious total compression ratio", f"{ratio:.1f}:1")
            if kind in {"docx", "xlsx", "pptx"}:
                metadata = inspect_office_metadata(archive, location, report)
                inspect_office_active_content(archive, location, report)
            if depth < limits.max_nested_depth:
                for info in nested[:32]:
                    nested_location = f"{location}!{info.filename}"
                    if info.file_size > limits.max_nested_member:
                        report.add(
                            "low",
                            "archive.nested_skipped",
                            nested_location,
                            "Nested archive was too large to inspect",
                            human_size(info.file_size),
                        )
                        continue
                    try:
                        inspect_zip(archive.read(info), nested_location, report, limits, depth + 1)
                    except (RuntimeError, NotImplementedError):
                        report.add("medium", "archive.nested_unreadable", nested_location, "Nested archive could not be inspected")
            return kind, metadata
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        report.add("high", "archive.malformed", location, "ZIP container is malformed or unreadable", str(exc))
        return "zip", metadata


def inspect_tar(path: Path, location: str, report: Report, limits: ScanLimits) -> None:
    try:
        with tarfile.open(path, "r:*") as archive:
            total = 0
            for index, member in enumerate(archive):
                if index >= limits.max_archive_members:
                    report.add("critical", "archive.member_count", location, "Archive contains too many entries")
                    break
                total += max(member.size, 0)
                member_location = f"{location}!{member.name}"
                if archive_name_is_unsafe(member.name):
                    report.add("critical", "archive.path_traversal", member_location, "Archive entry can escape the extraction directory")
                if member.issym() or member.islnk():
                    severity = "critical" if archive_name_is_unsafe(member.linkname) else "high"
                    report.add(severity, "archive.link", member_location, "Archive contains a filesystem link", member.linkname)
                if member.isdev() or member.isfifo():
                    report.add("critical", "archive.special_file", member_location, "Archive contains a device or special filesystem entry")
            if total > limits.max_archive_expanded:
                report.add("critical", "archive.expanded_size", location, "Archive expands beyond the configured safety limit", human_size(total))
    except (OSError, tarfile.TarError) as exc:
        report.add("high", "archive.malformed", location, "TAR container is malformed or unreadable", str(exc))


def inspect_compressed(path: Path, location: str, kind: str, report: Report, limits: ScanLimits) -> None:
    if tarfile.is_tarfile(path):
        inspect_tar(path, location, report, limits)
        return
    openers = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}
    opener = openers[kind]
    expanded = 0
    try:
        with opener(path, "rb") as handle:
            while True:
                block = handle.read(COPY_BUFFER)
                if not block:
                    break
                expanded += len(block)
                if expanded > limits.max_archive_expanded:
                    report.add(
                        "critical",
                        "archive.expanded_size",
                        location,
                        "Compressed stream expands beyond the configured safety limit",
                        f"more than {human_size(limits.max_archive_expanded)}",
                    )
                    return
        compressed = max(path.stat().st_size, 1)
        if expanded > 50 * 1024**2 and expanded / compressed > 100:
            report.add(
                "high",
                "archive.compression_ratio",
                location,
                "Compressed stream has a bomb-like expansion ratio",
                f"{expanded / compressed:.1f}:1 expands to {human_size(expanded)}",
            )
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError) as exc:
        report.add("high", "archive.malformed", location, f"{kind.upper()} stream is malformed or unreadable", str(exc))


PDF_PATTERNS = {
    b"/Author": "document author",
    b"/Creator": "creating application",
    b"/Producer": "PDF producer",
    b"/CreationDate": "creation timestamp",
    b"/ModDate": "modification timestamp",
    b"/Metadata": "XMP metadata",
}
PDF_ACTIVE = {
    b"/JavaScript": "embedded JavaScript",
    b"/JS": "embedded JavaScript",
    b"/OpenAction": "automatic open action",
    b"/Launch": "external launch action",
    b"/EmbeddedFile": "embedded file",
    b"/XFA": "XFA active form",
}


def inspect_pdf(path: Path, location: str, report: Report) -> list[str]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size <= 16 * 1024**2:
            data = handle.read()
        else:
            data = handle.read(8 * 1024**2)
            handle.seek(max(0, size - 8 * 1024**2))
            data += handle.read(8 * 1024**2)
    metadata = [name for marker, name in PDF_PATTERNS.items() if marker in data]
    active = [name for marker, name in PDF_ACTIVE.items() if marker in data]
    if metadata:
        report.add(
            "medium",
            "privacy.pdf_metadata",
            location,
            "PDF declares potentially identifying metadata",
            ", ".join(sorted(set(metadata))),
            "CarryProof reports PDF metadata but does not rewrite PDFs; use a dedicated PDF sanitizer.",
        )
    if active:
        report.add(
            "high",
            "pdf.active_content",
            location,
            "PDF contains active or embedded content markers",
            ", ".join(sorted(set(active))),
            "Open only in a hardened viewer and remove active content with a dedicated PDF tool.",
        )
    return sorted(set(metadata))


def inspect_svg(path: Path, location: str, report: Report) -> list[str]:
    if path.stat().st_size > 8 * 1024**2:
        report.add("low", "svg.large", location, "SVG is too large for structural inspection")
        return []
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        report.add("high", "svg.malformed", location, "SVG XML is malformed", str(exc))
        return []
    metadata: set[str] = set()
    active: set[str] = set()
    for element in root.iter():
        name = local_name(element.tag).lower()
        if name == "metadata":
            metadata.add("SVG metadata block")
        if name == "script":
            active.add("script element")
        for key, value in element.attrib.items():
            attr = local_name(key).lower()
            lowered = value.strip().lower()
            if attr.startswith("on"):
                active.add(f"event handler {attr}")
            if attr in {"href", "src"} and lowered.startswith(("http:", "https:", "file:", "javascript:")):
                active.add("external or executable reference")
    if metadata:
        report.add("medium", "privacy.svg_metadata", location, "SVG contains metadata", ", ".join(sorted(metadata)))
    if active:
        report.add(
            "critical",
            "svg.active_content",
            location,
            "SVG contains active content",
            ", ".join(sorted(active)),
            "Strip active SVG content before opening it in a browser or embedding it.",
        )
    return sorted(metadata)


CONTENT_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("critical", "content.private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("high", "content.aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("high", "content.github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("high", "content.jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("medium", "content.email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("low", "content.ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
)


def inspect_text_content(path: Path, location: str, kind: str, report: Report, limit: int) -> None:
    if path.stat().st_size > limit:
        report.add("info", "content.skipped_size", location, "Visible-content scan skipped for a large text file", human_size(path.stat().st_size))
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        report.add("low", "content.unreadable", location, "Text content could not be read", str(exc))
        return
    for severity, code, pattern in CONTENT_PATTERNS:
        count = len(pattern.findall(text))
        if count:
            label = code.split(".", 1)[1].replace("_", " ")
            report.add(
                severity,
                code,
                location,
                f"Visible content contains {label}",
                f"{count} match(es); values are intentionally omitted from the report",
                "Review visible content manually before sharing.",
            )
    if kind == "json":
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            report.add("medium", "data.invalid_json", location, "JSON is malformed", f"line {exc.lineno}, column {exc.colno}: {exc.msg}")
    elif kind == "jsonl":
        errors: list[str] = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {number}, column {exc.colno}: {exc.msg}")
                if len(errors) == 10:
                    break
        if errors:
            report.add("medium", "data.invalid_jsonl", location, "JSON Lines contains malformed records", "; ".join(errors))
    elif kind == "csv":
        try:
            rows = csv.reader(io.StringIO(text), strict=True)
            widths: Counter[int] = Counter(len(row) for row in rows)
            if len(widths) > 1:
                report.add("low", "data.csv_width", location, "CSV rows have inconsistent column counts", ", ".join(f"{width} columns: {count} rows" for width, count in widths.most_common(5)))
        except csv.Error as exc:
            report.add("medium", "data.invalid_csv", location, "CSV is malformed", str(exc))


def iter_target_files(target: Path, limits: ScanLimits) -> Iterator[tuple[Path, str]]:
    if target.is_symlink():
        raise CarryProofError("The scan target cannot be a symbolic link")
    if target.is_file():
        yield target, target.name
        return
    count = 0
    for root, dirs, files in os.walk(target, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not (Path(root) / name).is_symlink())
        for name in sorted(files):
            path = Path(root) / name
            rel = path.relative_to(target).as_posix()
            if path.is_symlink():
                continue
            if not path.is_file():
                continue
            count += 1
            if count > limits.max_files:
                raise CarryProofError(f"File count exceeds configured limit of {limits.max_files:,}")
            yield path, rel


def inspect_target(
    target: Path,
    *,
    content_scan: bool = False,
    limits: ScanLimits | None = None,
) -> Report:
    limits = limits or ScanLimits()
    target = target.expanduser().resolve()
    if not target.exists():
        raise CarryProofError(f"Path does not exist: {target}")
    report = Report(target.name or str(target), "file" if target.is_file() else "directory", content_scan)
    size_groups: dict[int, list[FileRecord]] = defaultdict(list)
    for path, rel in iter_target_files(target, limits):
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                head = handle.read(1024)
            kind = detect_type(path, head)
            digest = sha256_file(path)
        except OSError as exc:
            report.add("medium", "file.unreadable", rel, "File could not be read", str(exc))
            continue
        extension = path.suffix.lower()
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        record = FileRecord(rel, size, digest, kind, extension, mime)
        if kind in MAGIC_EXTENSIONS and extension not in MAGIC_EXTENSIONS[kind]:
            severity = "critical" if kind.endswith("executable") else "high"
            expected = ", ".join(sorted(item or "no extension" for item in MAGIC_EXTENSIONS[kind]))
            report.add(
                severity,
                "file.extension_mismatch",
                rel,
                "File content does not match its extension",
                f"Detected {kind}; expected extension: {expected}",
                "Verify the source before opening the file.",
            )
        if kind in {"pe-executable", "elf-executable", "mach-o-executable"}:
            report.add("high", "file.executable", rel, "File contains executable machine code", kind)
        if kind == "jpeg":
            record.metadata = inspect_jpeg(path, rel, report)
        elif kind == "png":
            record.metadata = inspect_png(path, rel, report)
        elif kind == "pdf":
            record.metadata = inspect_pdf(path, rel, report)
        elif kind == "svg":
            record.metadata = inspect_svg(path, rel, report)
        elif kind == "zip":
            actual_kind, metadata = inspect_zip(path, rel, report, limits)
            record.detected_type = actual_kind
            record.metadata = metadata
        elif kind == "tar":
            inspect_tar(path, rel, report, limits)
        elif kind in {"gzip", "bzip2", "xz"}:
            inspect_compressed(path, rel, kind, report, limits)
        elif kind in {"rar", "7z"}:
            report.add("low", "archive.unsupported", rel, f"{kind.upper()} archive contents were not inspected", remediation="Use a trusted format-specific inspector before extraction.")
        if content_scan and kind in {"text", "json", "jsonl", "csv", "xml", "html", "svg"}:
            inspect_text_content(path, rel, kind, report, limits.max_text_scan)
        report.files.append(record)
        size_groups[size].append(record)
    for size, records in sorted(size_groups.items()):
        by_hash: dict[str, list[FileRecord]] = defaultdict(list)
        for record in records:
            by_hash[record.sha256].append(record)
        for digest, matches in by_hash.items():
            if len(matches) < 2:
                continue
            matches.sort(key=lambda item: item.path)
            for duplicate in matches[1:]:
                duplicate.duplicate_of = matches[0].path
            group = {
                "sha256": digest,
                "size": size,
                "paths": [item.path for item in matches],
                "reclaimable_bytes": size * (len(matches) - 1),
            }
            report.duplicate_groups.append(group)
            report.add(
                "info",
                "storage.duplicates",
                matches[0].path,
                "Byte-identical duplicate files found",
                f"{len(matches)} copies; {human_size(group['reclaimable_bytes'])} potentially reclaimable",
            )
    return report


@contextlib.contextmanager
def atomic_output(destination: Path) -> Iterator[BinaryIO]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
    except BaseException:
        with contextlib.suppress(OSError):
            temp_path.unlink()
        raise


def atomic_copy(source: Path, destination: Path) -> None:
    with source.open("rb") as src, atomic_output(destination) as dst:
        shutil.copyfileobj(src, dst, COPY_BUFFER)


def clean_jpeg(source: Path, destination: Path) -> list[str]:
    removed: list[str] = []
    with source.open("rb") as src, atomic_output(destination) as dst:
        if src.read(2) != b"\xff\xd8":
            raise CarryProofError("Invalid JPEG signature")
        dst.write(b"\xff\xd8")
        while True:
            prefix = src.read(1)
            if not prefix:
                break
            while prefix != b"\xff":
                prefix = src.read(1)
                if not prefix:
                    break
            if not prefix:
                break
            marker_byte = src.read(1)
            while marker_byte == b"\xff":
                marker_byte = src.read(1)
            if not marker_byte:
                break
            marker = marker_byte[0]
            if marker in {0xD8, 0xD9, 0x01} or 0xD0 <= marker <= 0xD7:
                dst.write(b"\xff" + marker_byte)
                if marker == 0xD9:
                    break
                continue
            length_data = src.read(2)
            if len(length_data) != 2:
                raise CarryProofError("Truncated JPEG segment")
            length = struct.unpack(">H", length_data)[0]
            if length < 2:
                raise CarryProofError("Invalid JPEG segment length")
            payload = src.read(length - 2)
            if len(payload) != length - 2:
                raise CarryProofError("Truncated JPEG segment")
            remove = False
            if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                removed.append("EXIF")
                remove = True
            elif marker == 0xE1 and b"xap/1.0" in payload[:128]:
                removed.append("XMP")
                remove = True
            elif marker == 0xED:
                removed.append("IPTC/Photoshop")
                remove = True
            elif marker == 0xFE:
                removed.append("comment")
                remove = True
            if not remove:
                dst.write(b"\xff" + marker_byte + length_data + payload)
            if marker == 0xDA:
                shutil.copyfileobj(src, dst, COPY_BUFFER)
                break
    return [f"removed {name} metadata" for name in sorted(set(removed))] or ["no removable JPEG metadata found"]


def clean_png(source: Path, destination: Path) -> list[str]:
    removed: list[str] = []
    with source.open("rb") as src, atomic_output(destination) as dst:
        signature = src.read(8)
        if signature != b"\x89PNG\r\n\x1a\n":
            raise CarryProofError("Invalid PNG signature")
        dst.write(signature)
        src.seek(0)
        for kind, payload, crc in iter_png_chunks(src):
            if kind in PNG_METADATA_CHUNKS:
                removed.append(PNG_METADATA_CHUNKS[kind])
                continue
            dst.write(struct.pack(">I", len(payload)))
            dst.write(kind)
            dst.write(payload)
            dst.write(crc)
    return [f"removed {name}" for name in sorted(set(removed))] or ["no removable PNG metadata found"]


def xml_to_bytes(root: ET.Element) -> bytes:
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def sanitize_office_xml(name: str, data: bytes, strip_active: bool) -> tuple[bytes, list[str]]:
    actions: list[str] = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return data, actions
    lower = name.lower()
    if lower in {"docprops/core.xml", "docprops/app.xml", "docprops/custom.xml"}:
        for element in root.iter():
            key = local_name(element.tag)
            if key in OFFICE_PRIVATE_PROPERTIES or lower.endswith("custom.xml"):
                if element.text and element.text.strip():
                    element.text = ""
                    actions.append(f"cleared {key} property")
    if strip_active and lower.endswith(".rels"):
        for parent in root.iter():
            for child in list(parent):
                if local_name(child.tag) != "Relationship":
                    continue
                target = child.attrib.get("Target", "").lower()
                external = child.attrib.get("TargetMode", "").lower() == "external"
                risky_target = any(part in target for part in ("vbaproject", "activex", "embeddings", "externallinks", "customui"))
                if external or risky_target:
                    parent.remove(child)
                    actions.append("removed active/external relationship")
    if strip_active and lower == "[content_types].xml":
        for parent in root.iter():
            for child in list(parent):
                content_type = child.attrib.get("ContentType", "")
                lowered_type = content_type.lower()
                if "macroenabled.main+xml" in lowered_type:
                    replacements = {
                        "application/vnd.ms-word.document.macroenabled.main+xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                        "application/vnd.ms-excel.sheet.macroenabled.main+xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
                        "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
                    }
                    replacement = replacements.get(lowered_type)
                    if replacement:
                        child.set("ContentType", replacement)
                        actions.append("converted macro-enabled document declaration")
                        continue
                attributes = " ".join(child.attrib.values()).lower()
                if any(part in attributes for part in ("vba", "activex", "oleobject", "externallink")):
                    parent.remove(child)
                    actions.append("removed active content declaration")
    return (xml_to_bytes(root), actions) if actions else (data, actions)


def clean_office(source: Path, destination: Path, strip_active: bool) -> list[str]:
    actions: list[str] = []
    removed_patterns = ("vbaproject.bin", "/activex/", "/embeddings/", "/externallinks/", "/customui/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    os.close(descriptor)
    temp_path = Path(temporary)
    try:
        with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(
            temp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True
        ) as outgoing:
            for info in sorted(incoming.infolist(), key=lambda item: item.filename):
                name = info.filename.replace("\\", "/")
                lower = "/" + name.lower().lstrip("/")
                if strip_active and any(pattern in lower for pattern in removed_patterns):
                    actions.append(f"removed active part {name}")
                    continue
                data = incoming.read(info)
                if name.lower().endswith(".xml") or name.lower().endswith(".rels"):
                    data, xml_actions = sanitize_office_xml(name, data, strip_active)
                    actions.extend(xml_actions)
                output_info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
                output_info.compress_type = zipfile.ZIP_DEFLATED
                output_info.create_system = 3
                output_info.external_attr = (0o644 & 0xFFFF) << 16
                outgoing.writestr(output_info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(temp_path, destination)
    except BaseException:
        with contextlib.suppress(OSError):
            temp_path.unlink()
        raise
    return sorted(set(actions)) or ["no removable Office metadata found"]


def clean_svg(source: Path, destination: Path, strip_active: bool) -> list[str]:
    tree = ET.parse(source)
    root = tree.getroot()
    actions: list[str] = []
    for parent in root.iter():
        for child in list(parent):
            name = local_name(child.tag).lower()
            if name == "metadata" or (strip_active and name == "script"):
                parent.remove(child)
                actions.append(f"removed SVG {name}")
        if strip_active:
            for key in list(parent.attrib):
                attr = local_name(key).lower()
                value = parent.attrib[key].strip().lower()
                if attr.startswith("on") or (attr in {"href", "src"} and value.startswith(("http:", "https:", "file:", "javascript:"))):
                    del parent.attrib[key]
                    actions.append("removed SVG active/external attribute")
    with atomic_output(destination) as handle:
        handle.write(xml_to_bytes(root))
    return sorted(set(actions)) or ["no removable SVG metadata found"]


def sanitize_file(source: Path, destination: Path, kind: str, strip_active: bool) -> list[str]:
    try:
        if kind == "jpeg":
            return clean_jpeg(source, destination)
        if kind == "png":
            return clean_png(source, destination)
        if kind in {"docx", "xlsx", "pptx"}:
            return clean_office(source, destination, strip_active)
        if kind == "svg":
            return clean_svg(source, destination, strip_active)
        atomic_copy(source, destination)
        if kind == "pdf":
            return ["copied unchanged: PDF rewriting is intentionally unsupported"]
        return ["copied unchanged"]
    except (OSError, CarryProofError, zipfile.BadZipFile, ET.ParseError) as exc:
        atomic_copy(source, destination)
        return [f"sanitization failed; copied unchanged: {exc}"]


def clean_target(
    target: Path,
    destination: Path,
    before: Report,
    *,
    strip_active: bool = False,
) -> dict[str, list[str]]:
    target = target.resolve()
    destination = destination.resolve()
    if destination == target or target in destination.parents:
        raise CarryProofError("Output must not be the input path or a child of it")
    if destination.exists():
        raise CarryProofError(f"Output already exists: {destination}")
    destination.mkdir(parents=True)
    record_by_path = {record.path: record for record in before.files}
    cleaning: dict[str, list[str]] = {}
    for source, rel in iter_target_files(target, ScanLimits(max_files=max(len(before.files) + 1, 1))):
        record = record_by_path.get(rel)
        if record is None:
            continue
        output_rel = PurePosixPath(rel if target.is_dir() else source.name)
        renamed_action: str | None = None
        macro_extensions = {".docm": ".docx", ".xlsm": ".xlsx", ".pptm": ".pptx"}
        source_suffix = output_rel.suffix.lower()
        if strip_active and source_suffix in macro_extensions:
            safe_suffix = macro_extensions[source_suffix]
            output_rel = output_rel.with_name(f"{output_rel.stem}.sanitized{safe_suffix}")
            renamed_action = f"renamed macro-enabled {source_suffix} output to {safe_suffix}"
        output = destination.joinpath(*output_rel.parts)
        if output.exists():
            raise CarryProofError(f"Prepared filename collision: {output_rel.as_posix()}")
        actions = sanitize_file(source, output, record.detected_type, strip_active)
        if renamed_action:
            actions.insert(0, renamed_action)
        record.cleaning = actions
        record.prepared_path = output_rel.as_posix()
        cleaning[rel] = actions
    return cleaning


def deterministic_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_json(path: Path, value: Any, *, pretty: bool = True) -> None:
    data = (
        (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if pretty
        else deterministic_json(value)
    )
    with atomic_output(path) as handle:
        handle.write(data)


def zip_info(name: str, mode: int = 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info._compresslevel = 9
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    return info


def bundle_manifest(root: Path, report: Report, after: Report | None = None) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path, rel in iter_target_files(root, ScanLimits()):
        files.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return {
        "schema": 1,
        "tool": APP_NAME,
        "version": VERSION,
        "source_name": report.source_name,
        "original_summary": report.summary(),
        "prepared_summary": after.summary() if after else report.summary(),
        "files": sorted(files, key=lambda item: item["path"]),
    }


def make_bundle(
    root: Path,
    destination: Path,
    report: Report,
    report_html: bytes | None = None,
    after: Report | None = None,
) -> dict[str, Any]:
    manifest = bundle_manifest(root, report, after)
    if any(entry["path"] in BUNDLE_METADATA for entry in manifest["files"]):
        raise CarryProofError("An input filename conflicts with reserved bundle metadata")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    os.close(descriptor)
    temp_path = Path(temporary)
    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as archive:
            for path, rel in iter_target_files(root, ScanLimits()):
                info = zip_info(rel)
                info.file_size = path.stat().st_size
                with path.open("rb") as source, archive.open(info, "w") as output:
                    shutil.copyfileobj(source, output, COPY_BUFFER)
            archive.writestr(zip_info("CARRYPROOF-MANIFEST.json"), deterministic_json(manifest), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
            report_payload: dict[str, Any] = {"original": report.as_dict(include_generated=False)}
            if after is not None:
                report_payload["prepared"] = after.as_dict(include_generated=False)
            archive.writestr(zip_info("CARRYPROOF-REPORT.json"), deterministic_json(report_payload), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
            if report_html is not None:
                archive.writestr(zip_info("CARRYPROOF-REPORT.html"), report_html, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(temp_path, destination)
    except BaseException:
        with contextlib.suppress(OSError):
            temp_path.unlink()
        raise
    return manifest


def verify_bundle(path: Path) -> dict[str, Any]:
    checked = 0
    failures: list[str] = []
    manifest: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            limits = ScanLimits()
            names = [entry.filename for entry in members]
            if len(members) > limits.max_files + len(BUNDLE_METADATA):
                raise CarryProofError("Bundle file count exceeds verification limit")
            if sum(entry.file_size for entry in members) > limits.max_archive_expanded:
                raise CarryProofError("Bundle expanded size exceeds verification limit")
            if len(names) != len(set(names)) or any(archive_name_is_unsafe(name) for name in names):
                raise CarryProofError("Bundle contains unsafe or duplicate paths")
            with archive.open("CARRYPROOF-MANIFEST.json") as handle:
                manifest = json.loads(read_limited(handle, limits.max_nested_member))
            if not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("tool") != APP_NAME:
                raise CarryProofError("Unsupported bundle manifest")
            entries = manifest.get("files")
            if not isinstance(entries, list):
                raise CarryProofError("Bundle manifest has no file inventory")
            if len(entries) > limits.max_files:
                raise CarryProofError("Bundle payload count exceeds verification limit")
            seen: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise CarryProofError("Invalid bundle file entry")
                name, size, expected = entry.get("path"), entry.get("size"), entry.get("sha256")
                if not isinstance(name, str) or archive_name_is_unsafe(name) or name in seen or name in BUNDLE_METADATA:
                    raise CarryProofError("Unsafe, duplicate, or reserved bundle manifest path")
                if type(size) is not int or size < 0 or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                    raise CarryProofError("Invalid bundle file size or hash")
                seen.add(name)
            if set(names) - BUNDLE_METADATA != seen:
                raise CarryProofError("Bundle entries do not match the manifest inventory")
            bad_crc = archive.testzip()
            if bad_crc:
                raise CarryProofError(f"ZIP CRC failed for {bad_crc}")
            for entry in entries:
                name = entry["path"]
                with archive.open(name) as handle:
                    actual = sha256_stream(handle)
                checked += 1
                if archive.getinfo(name).file_size != entry["size"] or not hmac.compare_digest(actual, entry["sha256"]):
                    failures.append(f"size or hash mismatch: {name}")
    except (CarryProofError, OSError, KeyError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error, lzma.LZMAError) as exc:
        failures.append(str(exc))
    return {"ok": not failures, "checked": checked, "failures": failures, "manifest": manifest}


def xor_into(target: bytearray, data: bytes) -> None:
    for index, value in enumerate(data):
        target[index] ^= value


def create_parity(
    source: Path,
    destination: Path,
    *,
    chunk_size: int = 1024 * 1024,
    stripe_width: int = 8,
) -> dict[str, Any]:
    if chunk_size < 4096 or chunk_size > 64 * 1024**2:
        raise CarryProofError("Chunk size must be between 4 KiB and 64 MiB")
    if not 2 <= stripe_width <= 64:
        raise CarryProofError("Stripe width must be between 2 and 64")
    file_size = source.stat().st_size
    hashes: list[str] = []
    parity_sizes: list[int] = []
    descriptor, parity_temp_name = tempfile.mkstemp(prefix=".carryproof-parity-", suffix=".tmp", dir=destination.parent)
    os.close(descriptor)
    parity_temp = Path(parity_temp_name)
    try:
        full_digest = hashlib.sha256()
        with source.open("rb") as incoming, parity_temp.open("wb") as parity_out:
            while True:
                stripe: list[bytes] = []
                for _ in range(stripe_width):
                    chunk = incoming.read(chunk_size)
                    if not chunk:
                        break
                    stripe.append(chunk)
                    hashes.append(hashlib.sha256(chunk).hexdigest())
                    full_digest.update(chunk)
                if not stripe:
                    break
                width = max(len(chunk) for chunk in stripe)
                parity = bytearray(width)
                for chunk in stripe:
                    xor_into(parity, chunk)
                parity_out.write(parity)
                parity_sizes.append(width)
        header = {
            "schema": 1,
            "algorithm": "xor-stripe-v1",
            "source_name": source.name,
            "file_size": file_size,
            "file_sha256": full_digest.hexdigest(),
            "chunk_size": chunk_size,
            "stripe_width": stripe_width,
            "chunk_hashes": hashes,
            "parity_sizes": parity_sizes,
        }
        header_bytes = deterministic_json(header)
        with atomic_output(destination) as output:
            output.write(PARITY_MAGIC)
            output.write(struct.pack(">Q", len(header_bytes)))
            output.write(header_bytes)
            with parity_temp.open("rb") as parity_in:
                shutil.copyfileobj(parity_in, output, COPY_BUFFER)
        return header
    finally:
        with contextlib.suppress(OSError):
            parity_temp.unlink()


def read_parity_header(handle: BinaryIO) -> tuple[dict[str, Any], int]:
    if handle.read(len(PARITY_MAGIC)) != PARITY_MAGIC:
        raise CarryProofError("Not a CarryProof parity file")
    raw_length = handle.read(8)
    if len(raw_length) != 8:
        raise CarryProofError("Truncated parity header")
    length = struct.unpack(">Q", raw_length)[0]
    if length > 128 * 1024**2:
        raise CarryProofError("Parity header is unreasonably large")
    raw = handle.read(length)
    if len(raw) != length:
        raise CarryProofError("Truncated parity header")
    try:
        header = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CarryProofError(f"Malformed parity header: {exc}") from exc
    if header.get("algorithm") != "xor-stripe-v1":
        raise CarryProofError("Unsupported parity algorithm")
    return header, len(PARITY_MAGIC) + 8 + length


def recover_with_parity(source: Path, parity_path: Path, destination: Path) -> dict[str, Any]:
    with parity_path.open("rb") as parity_handle:
        header, _offset = read_parity_header(parity_handle)
        chunk_size = int(header["chunk_size"])
        stripe_width = int(header["stripe_width"])
        file_size = int(header["file_size"])
        hashes = list(header["chunk_hashes"])
        parity_sizes = list(header["parity_sizes"])
        expected_chunks = (file_size + chunk_size - 1) // chunk_size if file_size else 0
        if len(hashes) != expected_chunks:
            raise CarryProofError("Parity header has an inconsistent chunk table")
        repaired = 0
        descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        temp_path = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as damaged:
                for stripe_index, parity_size in enumerate(parity_sizes):
                    parity = parity_handle.read(parity_size)
                    if len(parity) != parity_size:
                        raise CarryProofError("Parity payload is truncated")
                    start_chunk = stripe_index * stripe_width
                    stripe_count = min(stripe_width, expected_chunks - start_chunk)
                    chunks: list[bytes] = []
                    bad: list[int] = []
                    for local_index in range(stripe_count):
                        chunk_index = start_chunk + local_index
                        expected_length = min(chunk_size, file_size - chunk_index * chunk_size)
                        damaged.seek(chunk_index * chunk_size)
                        chunk = damaged.read(expected_length)
                        chunks.append(chunk)
                        if len(chunk) != expected_length or not hmac.compare_digest(
                            hashlib.sha256(chunk).hexdigest(), hashes[chunk_index]
                        ):
                            bad.append(local_index)
                    if len(bad) > 1:
                        raise CarryProofError(
                            f"Stripe {stripe_index} has {len(bad)} damaged chunks; XOR parity can repair only one"
                        )
                    if bad:
                        missing = bad[0]
                        recovered = bytearray(parity)
                        for index, chunk in enumerate(chunks):
                            if index != missing:
                                xor_into(recovered, chunk)
                        chunk_index = start_chunk + missing
                        expected_length = min(chunk_size, file_size - chunk_index * chunk_size)
                        restored = bytes(recovered[:expected_length])
                        if hashlib.sha256(restored).hexdigest() != hashes[chunk_index]:
                            raise CarryProofError(f"Recovered chunk {chunk_index} failed its integrity hash")
                        chunks[missing] = restored
                        repaired += 1
                    for chunk in chunks:
                        output.write(chunk)
                output.truncate(file_size)
                output.flush()
                os.fsync(output.fileno())
            actual = sha256_file(temp_path)
            if not hmac.compare_digest(actual, str(header["file_sha256"])):
                raise CarryProofError("Recovered file failed its final SHA-256 check")
            os.replace(temp_path, destination)
            return {"ok": True, "repaired_chunks": repaired, "sha256": actual, "bytes": file_size}
        except BaseException:
            with contextlib.suppress(OSError):
                temp_path.unlink()
            raise


def report_payload(
    original: Report, prepared: Report | None = None, *, include_generated: bool = True
) -> dict[str, Any]:
    payload: dict[str, Any] = {"original": original.as_dict(include_generated=include_generated)}
    if prepared is not None:
        payload["prepared"] = prepared.as_dict(include_generated=include_generated)
    return payload


def transformation_ledger(original: Report, prepared: Report) -> list[dict[str, Any]]:
    prepared_by_path = {record.path: record for record in prepared.files}
    ledger: list[dict[str, Any]] = []
    for before in sorted(original.files, key=lambda item: item.path.casefold()):
        prepared_path = before.prepared_path or before.path
        after = prepared_by_path.get(prepared_path)
        ledger.append(
            {
                "original_path": before.path,
                "prepared_path": prepared_path,
                "original_sha256": before.sha256,
                "prepared_sha256": after.sha256 if after else None,
                "original_size": before.size,
                "prepared_size": after.size if after else None,
                "changed": bool(after and not hmac.compare_digest(before.sha256, after.sha256)),
                "actions": before.cleaning or ["copied unchanged"],
            }
        )
    return ledger


def capsule_manifest(root: Path, original: Report, prepared: Report) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    prepared_by_path = {record.path: record for record in prepared.files}
    paths = list(iter_target_files(root, ScanLimits()))
    if {rel for _, rel in paths} != set(prepared_by_path):
        raise CarryProofError("Prepared file inventory changed after inspection")
    for path, rel in paths:
        record = prepared_by_path[rel]
        files.append(
            {
                "path": rel,
                "size": record.size,
                "sha256": record.sha256,
                "type": record.detected_type,
                "mime": "application/octet-stream",
            }
        )
    original_summary = original.summary()
    prepared_summary = prepared.summary()
    return {
        "schema": 1,
        "kind": "proof-carrying-handoff",
        "tool": APP_NAME,
        "version": VERSION,
        "source_name": original.source_name,
        "original_summary": original_summary,
        "prepared_summary": prepared_summary,
        "removed_findings": max(0, original_summary["findings"] - prepared_summary["findings"]),
        "transformations": transformation_ledger(original, prepared),
        "files": files,
    }


CAPSULE_HEAD = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:; media-src blob:; connect-src 'none'; base-uri 'none'; form-action 'none'"><title>CarryProof offline capsule</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;letter-spacing:0;color:#171b1f;background:#f4f6f3;--paper:#f4f6f3;--surface:#fff;--line:#d5dcda;--muted:#667279;--teal:#087f76;--teal-soft:#dcefeb;--red:#b4232f;--red-soft:#f8dde0;--yellow:#8c6900;--yellow-soft:#f6edc8;--blue:#315b85}*{box-sizing:border-box}body{margin:0;min-width:0}button{font:inherit;letter-spacing:0;cursor:pointer}.top{height:68px;background:var(--surface);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 clamp(16px,4vw,52px);position:sticky;top:0;z-index:10}.brand{display:flex;align-items:center;gap:11px}.mark{width:36px;height:36px;border-radius:6px;display:grid;place-items:center;background:#171b1f;color:#fff;font-size:12px;font-weight:900}.brand strong{display:block}.brand small{display:block;color:var(--muted);font-size:11px}.offline{font-size:11px;font-weight:800;color:var(--teal);background:var(--teal-soft);padding:6px 9px;border-radius:999px}.shell{max-width:1180px;margin:auto;padding:38px clamp(18px,4vw,52px) 64px}.intro{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(260px,.6fr);gap:42px;align-items:end;padding-bottom:34px;border-bottom:1px solid var(--line)}.eyebrow{margin:0 0 9px;color:var(--teal);font-size:12px;font-weight:900;text-transform:uppercase}.intro h1{font-size:30px;line-height:1.02;letter-spacing:0;margin:0 0 14px;max-width:760px}.intro p{overflow-wrap:anywhere;color:var(--muted);line-height:1.6;margin:0;max-width:720px}.seal{border-left:4px solid var(--teal);padding:4px 0 4px 16px;min-width:0}.seal span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;font-weight:800;margin-bottom:7px}.seal code{display:block;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;color:var(--blue)}.seal small{display:block;color:var(--muted);margin-top:8px;line-height:1.4}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));background:var(--surface);border:1px solid var(--line);border-radius:7px;overflow:hidden;margin:28px 0}.metric{padding:18px;border-right:1px solid var(--line)}.metric:last-child{border:0}.metric span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;font-weight:800;margin-bottom:8px}.metric strong{font-size:26px;display:block;overflow-wrap:anywhere}.metric strong.good{color:var(--teal)}.section-head{display:flex;align-items:end;justify-content:space-between;gap:18px;margin:34px 0 13px}.section-head h2{font-size:19px;margin:0 0 4px}.section-head p{margin:0;color:var(--muted);font-size:13px}.actions{display:flex;gap:8px}.action{border:1px solid var(--line);background:var(--surface);border-radius:6px;padding:9px 12px;font-weight:800;color:#273137}.action.primary{background:#171b1f;color:#fff;border-color:#171b1f}.action:disabled{opacity:.55;cursor:wait}.panel{background:var(--surface);border:1px solid var(--line);border-radius:7px;overflow:hidden}.file-row{display:grid;grid-template-columns:minmax(180px,1fr) 100px 150px 110px;gap:14px;align-items:center;padding:13px 15px;border-bottom:1px solid var(--line)}.file-row:last-child{border:0}.file-row.head{background:#edf1ef;color:var(--muted);font-size:10px;text-transform:uppercase;font-weight:900}.path{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.meta{font-size:12px;color:var(--muted)}.state{font-size:11px;font-weight:900;color:var(--yellow);background:var(--yellow-soft);padding:5px 7px;border-radius:4px;display:inline-block}.state.ok{color:var(--teal);background:var(--teal-soft)}.state.bad{color:var(--red);background:var(--red-soft)}.download{border:0;background:transparent;color:var(--teal);font-weight:900;padding:5px;text-align:left}.ledger-row{display:grid;grid-template-columns:minmax(170px,1fr) 74px minmax(240px,1.25fr);gap:16px;padding:14px 15px;border-bottom:1px solid var(--line);align-items:start}.ledger-row:last-child{border:0}.ledger-row.head{background:#edf1ef;color:var(--muted);font-size:10px;text-transform:uppercase;font-weight:900}.change{font-size:11px;font-weight:900;text-transform:uppercase;color:var(--teal)}.change.same{color:var(--muted)}.ledger-row p{margin:0;color:var(--muted);font-size:12px;line-height:1.5}.notice{margin-top:28px;border-top:1px solid var(--line);padding-top:18px;display:flex;justify-content:space-between;gap:22px;color:var(--muted);font-size:11px;line-height:1.5}.toast{position:fixed;right:18px;bottom:18px;background:#171b1f;color:#fff;border-radius:6px;padding:11px 14px;font-size:12px;opacity:0;transform:translateY(7px);transition:.18s;pointer-events:none}.toast.show{opacity:1;transform:none}@media(max-width:800px){.intro{grid-template-columns:1fr;gap:22px}.metrics{grid-template-columns:1fr 1fr}.metric:nth-child(2){border-right:0}.metric:nth-child(-n+2){border-bottom:1px solid var(--line)}.file-row{grid-template-columns:minmax(150px,1fr) 90px 100px}.file-row>*:nth-child(3){display:none}.ledger-row{grid-template-columns:minmax(0,1fr) 80px}.ledger-row>*:nth-child(3){grid-column:1/-1}.section-head{align-items:flex-start;flex-direction:column}.actions{width:100%}.action{flex:1}.notice{flex-direction:column}}@media(max-width:480px){.brand small{display:none}.shell{padding-top:26px}.metrics{grid-template-columns:1fr 1fr}.metric strong{font-size:21px}.file-row{grid-template-columns:minmax(120px,1fr) 82px}.file-row>*:nth-child(2){display:none}.ledger-row{grid-template-columns:minmax(0,1fr) 80px}}
.brand{min-width:0}.brand .mark{flex:0 0 auto}.brand>div{min-width:0}.brand strong{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.top{gap:12px}.offline{flex:0 0 auto;white-space:nowrap}.intro h1{font-size:30px}.intro{padding-bottom:22px}.seal small{font-weight:700}.file-name{min-width:0;display:flex;flex-direction:column;align-items:flex-start;gap:7px}.download{font-size:13px;font-weight:800;min-height:36px}.download:disabled{opacity:.5;cursor:wait}.fingerprints{margin-top:8px;font-size:11px;color:var(--muted)}.fingerprints summary{cursor:pointer}.fingerprints span{display:block;margin:8px 0 3px}.fingerprints code{display:block;overflow-wrap:anywhere;font-size:10px}.verification-message{min-height:40px;color:var(--muted);font-size:12px;line-height:1.5;margin:0 0 14px}.verification-message.failed{color:var(--red)}.actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));width:420px;max-width:100%}.action{min-height:44px;overflow-wrap:anywhere}.state{white-space:nowrap}.notice{display:block}.notice p{margin:0 0 5px}@media(max-width:800px){.actions{width:100%;min-height:58px}}
</style></head><body>
<header class="top"><div class="brand"><span class="mark">CP</span><div><strong>CarryProof capsule</strong><small>proof-carrying file handoff</small></div></div><span class="offline">offline capsule</span></header>
<main class="shell">
  <section class="intro">
    <div><p class="eyebrow">File handoff</p><h1>CarryProof capsule</h1><p id="subtitle"></p></div>
    <div class="seal"><span>Manifest SHA-256</span><code id="seal">__CAPSULE_SEAL__</code><small id="sealStatus">Not checked</small></div>
  </section>
  <section id="metrics" class="metrics"></section>
  <section>
    <div class="section-head"><div><h2>Prepared payloads</h2></div><div class="actions">
      <button id="verifyAll" class="action primary">Verify all payloads</button>
      <button id="tamperProbe" class="action">Test one-byte change</button>
    </div></div>
    <p id="verificationMessage" class="verification-message" role="status" aria-live="polite">Not checked.</p>
    <div class="panel"><div class="file-row head"><span>File / status</span><span>Size</span><span>SHA-256</span><span>Action</span></div><div id="files"></div></div>
  </section>
  <section>
    <div class="section-head"><div><h2>Recorded transformations</h2></div></div>
    <div class="panel"><div class="ledger-row head"><span>Path</span><span>Bytes</span><span>Recorded action</span></div><div id="ledger"></div></div>
  </section>
  <footer class="notice">
    <p>Prepared copies can still contain findings. Matching hashes do not establish malware safety or sender identity. Scores are heuristic, not probabilities.</p>
    <p>The manifest seal does not cover this page's verifier code. For a sensitive handoff, independently check the complete HTML file hash before opening it.</p>
  </footer>
</main>
<script id="capsule-manifest" type="application/json">'''


CAPSULE_FILES_OPEN = r'''</script><script id="capsule-files" type="application/json">['''


CAPSULE_TAIL = r''']</script><script>
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hex = buffer => Array.from(new Uint8Array(buffer), v => v.toString(16).padStart(2, '0')).join('');
let manifestText, manifest, payloads, seal;
function bytes(number) {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let value = Number(number) || 0, index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return (index ? value.toFixed(1) : value.toFixed(0)) + ' ' + units[index];
}
function decode(value) {
  if (typeof value !== 'string' || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error('Invalid Base64 payload.');
  }
  const raw = atob(value), output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) output[i] = raw.charCodeAt(i);
  return output;
}
async function digest(data) {
  if (!window.crypto?.subtle) {
    throw new Error('Web Crypto is unavailable here. Download the capsule and open the local HTML in a current browser, or verify it with the CLI.');
  }
  return hex(await window.crypto.subtle.digest('SHA-256', data));
}
function lockControls(locked) {
  document.querySelectorAll('#verifyAll,#tamperProbe,[data-file]').forEach(button => button.disabled = locked);
}
function message(text, failed = false) {
  $('verificationMessage').textContent = text;
  $('verificationMessage').classList.toggle('failed', failed);
}
async function verifyManifest() {
  if (await digest(new TextEncoder().encode(manifestText)) !== seal) {
    $('sealStatus').textContent = 'Manifest mismatch';
    throw new Error('Manifest seal mismatch. Downloads are blocked.');
  }
  if (manifest.schema !== 1 || manifest.kind !== 'proof-carrying-handoff' ||
      !Array.isArray(manifest.files) || !Array.isArray(payloads) ||
      payloads.length !== manifest.files.length) {
    throw new Error('Invalid manifest or payload count.');
  }
  const names = new Set();
  for (let i = 0; i < manifest.files.length; i++) {
    const file = manifest.files[i], payload = payloads[i];
    if (!file || typeof file.path !== 'string' || !file.path ||
        /[\\:\0]/.test(file.path) || file.path.split('/').some(p => !p || p === '.' || p === '..') ||
        names.has(file.path) || !Number.isSafeInteger(file.size) || file.size < 0 ||
        !/^[0-9a-f]{64}$/.test(file.sha256) || !payload || payload.path !== file.path) {
      throw new Error('Invalid, duplicate, or mismatched payload entry.');
    }
    names.add(file.path);
  }
  $('sealStatus').textContent = 'Manifest matches';
}
async function payloadMatches(data, expected) {
  return data.length === expected.size && await digest(data) === expected.sha256;
}
async function verifyFile(index) {
  const expected = manifest.files[index], state = $('state-' + index);
  try {
    const data = decode(payloads[index].data);
    if (!await payloadMatches(data, expected)) throw new Error(expected.path + ': size or SHA-256 mismatch.');
    state.textContent = 'Verified';
    state.className = 'state ok';
    return data;
  } catch (error) {
    state.textContent = 'Failed';
    state.className = 'state bad';
    throw error;
  }
}
async function downloadFile(index) {
  lockControls(true);
  try {
    await verifyManifest();
    const data = await verifyFile(index);
    const url = URL.createObjectURL(new Blob([data], {type: 'application/octet-stream'}));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = manifest.files[index].path.split('/').pop() || 'carryproof-file';
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    message('Manifest and payload match. Download released: ' + manifest.files[index].path);
  } catch (error) {
    message(error.message, true);
  } finally {
    lockControls(false);
  }
}
async function verifyAll() {
  lockControls(true);
  try {
    await verifyManifest();
    for (let i = 0; i < manifest.files.length; i++) {
      $('verifyAll').textContent = 'Verifying ' + (i + 1) + ' / ' + manifest.files.length;
      await verifyFile(i);
    }
    $('verifyAll').textContent = 'All payloads verified';
    message('Manifest and all ' + manifest.files.length + ' payloads match. Integrity is not a malware verdict.');
  } catch (error) {
    $('verifyAll').textContent = 'Verification failed';
    message(error.message, true);
  } finally {
    lockControls(false);
  }
}
async function testOneByteChange() {
  lockControls(true);
  try {
    await verifyManifest();
    const index = manifest.files.findIndex(file => file.size > 0);
    if (index < 0) throw new Error('No non-empty payload to test.');
    const changed = await verifyFile(index);
    changed[0] ^= 1;
    const rejected = !await payloadMatches(changed, manifest.files[index]);
    message(rejected
      ? 'One-byte change rejected by SHA-256. Only an in-memory copy was altered; embedded files are unchanged.'
      : 'Unexpected result: the changed payload passed verification.', !rejected);
  } catch (error) {
    message(error.message, true);
  } finally {
    lockControls(false);
  }
}
function render() {
  const before = manifest.original_summary, after = manifest.prepared_summary;
  $('subtitle').textContent = manifest.source_name + ' / prepared handoff';
  const metrics = [
    ['Before score', before.risk_score + '/100', ''],
    ['Prepared score', after.risk_score + '/100', after.risk_score === 0 ? 'good' : ''],
    ['Fewer findings', manifest.removed_findings, ''],
    ['Payloads', manifest.files.length, '']
  ];
  $('metrics').innerHTML = metrics.map(m => '<div class="metric"><span>' + esc(m[0]) +
    '</span><strong class="' + m[2] + '">' + esc(m[1]) + '</strong></div>').join('');
  $('files').innerHTML = manifest.files.map((file, index) => '<div class="file-row"><div class="file-name">' +
    '<span class="path">' + esc(file.path) + '</span><span id="state-' + index +
    '" class="state">Not checked</span></div><span class="meta">' + bytes(file.size) +
    '</span><code class="path" title="' + esc(file.sha256) + '">' + esc(file.sha256.slice(0, 16)) +
    '</code><button class="download" data-file="' + index + '" aria-label="Verify and download ' +
    esc(file.path) + '">Download</button></div>').join('');
  $('ledger').innerHTML = manifest.transformations.map(item => '<div class="ledger-row"><span class="path">' +
    esc(item.original_path) + (item.original_path !== item.prepared_path ? '<br><span class="meta">-&gt; ' +
    esc(item.prepared_path) + '</span>' : '') + '</span><span class="change ' + (item.changed ? '' : 'same') +
    '">' + (item.changed ? 'Changed' : 'Unchanged') + '</span><div><p>' +
    item.actions.map(esc).join('; ') + '</p><details class="fingerprints"><summary>Fingerprints</summary>' +
    '<span>Original SHA-256</span><code>' + esc(item.original_sha256) +
    '</code><span>Prepared SHA-256</span><code>' + esc(item.prepared_sha256 || 'Not available') +
    '</code></details></div></div>').join('');
  document.querySelectorAll('[data-file]').forEach(button => {
    button.onclick = () => downloadFile(Number(button.dataset.file));
  });
}
try {
  manifestText = $('capsule-manifest').textContent;
  manifest = JSON.parse(manifestText);
  payloads = JSON.parse($('capsule-files').textContent);
  seal = document.querySelector('meta[name="capsule-seal"]').content;
  render();
  $('verifyAll').onclick = verifyAll;
  $('tamperProbe').onclick = testOneByteChange;
} catch (error) {
  lockControls(true);
  message('Capsule could not be read: ' + error.message, true);
}
</script></body></html>'''


def create_capsule(root: Path, destination: Path, original: Report, prepared: Report) -> dict[str, Any]:
    manifest = capsule_manifest(root, original, prepared)
    canonical = deterministic_json(manifest).replace(b"<", b"\\u003c")
    seal = hashlib.sha256(canonical).hexdigest()
    head = CAPSULE_HEAD.replace("__CAPSULE_SEAL__", seal).replace(
        "<title>CarryProof offline capsule</title>",
        f'<meta name="capsule-seal" content="{seal}"><title>CarryProof offline capsule</title>',
    )
    paths = list(iter_target_files(root, ScanLimits()))
    if [rel for _, rel in paths] != [entry["path"] for entry in manifest["files"]]:
        raise CarryProofError("Prepared file inventory changed while creating the capsule")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with atomic_output(destination) as output:
        output.write(head.encode("utf-8"))
        output.write(canonical)
        output.write(CAPSULE_FILES_OPEN.encode("utf-8"))
        for index, (path, rel) in enumerate(paths):
            if index:
                output.write(b",")
            expected = manifest["files"][index]
            entry = json.dumps(
                {"path": rel, "data": ""}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).replace("<", "\\u003c")
            prefix, suffix = entry.split('""', 1)
            output.write(prefix.encode("utf-8"))
            output.write(b'"')
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as source:
                for block in iter(lambda: source.read(CAPSULE_BUFFER), b""):
                    digest.update(block)
                    size += len(block)
                    output.write(base64.b64encode(block))
            if size != expected["size"] or not hmac.compare_digest(digest.hexdigest(), expected["sha256"]):
                raise CarryProofError(f"Prepared file changed while the capsule was being created: {rel}")
            output.write(b'"')
            output.write(suffix.encode("utf-8"))
        output.write(CAPSULE_TAIL.encode("utf-8"))
    return {"manifest": manifest, "seal": seal, "sha256": sha256_file(destination), "bytes": destination.stat().st_size}


class CapsuleDataParser(HTMLParser):
    """Read the two data islands without evaluating any capsule code."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.seal: str | None = None
        self.islands: dict[str, list[str]] = {}
        self.active: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if len(attributes) != len(attrs):
            raise CarryProofError("Duplicate HTML attributes are not allowed in a capsule")
        if tag == "meta" and attributes.get("name") == "capsule-seal":
            if self.seal is not None:
                raise CarryProofError("Duplicate capsule seal")
            self.seal = attributes.get("content") or ""
        if tag == "script" and attributes.get("id") in {"capsule-manifest", "capsule-files"}:
            name = str(attributes["id"])
            if name in self.islands or attributes.get("type") != "application/json":
                raise CarryProofError("Invalid or duplicate capsule data island")
            self.islands[name] = []
            self.active = name

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self.active = None

    def handle_data(self, data: str) -> None:
        if self.active is not None:
            self.islands[self.active].append(data)


def verify_capsule(path: Path, expected_sha256: str | None = None) -> dict[str, Any]:
    checked = 0
    failures: list[str] = []
    actual_sha256 = ""
    seal = ""
    try:
        with path.open("rb") as source:
            document = read_limited(source, MAX_CAPSULE_VERIFY_BYTES)
        actual_sha256 = hashlib.sha256(document).hexdigest()
        if expected_sha256 is not None:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
                raise CarryProofError("Expected SHA-256 must contain exactly 64 hexadecimal characters")
            if not hmac.compare_digest(actual_sha256, expected_sha256.lower()):
                raise CarryProofError("Whole-capsule SHA-256 does not match the trusted value")
        parser = CapsuleDataParser()
        parser.feed(document.decode("utf-8"))
        parser.close()
        if parser.active is not None or set(parser.islands) != {"capsule-manifest", "capsule-files"}:
            raise CarryProofError("Capsule data islands are missing or incomplete")
        seal = parser.seal or ""
        manifest_text = "".join(parser.islands["capsule-manifest"])
        if not re.fullmatch(r"[0-9a-f]{64}", seal) or not hmac.compare_digest(
            hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(), seal
        ):
            raise CarryProofError("Manifest seal mismatch")
        manifest = json.loads(manifest_text)
        if not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("kind") != "proof-carrying-handoff":
            raise CarryProofError("Unsupported capsule manifest")
        canonical = deterministic_json(manifest).replace(b"<", b"\\u003c")
        if canonical != manifest_text.encode("utf-8"):
            raise CarryProofError("Capsule manifest is not canonically serialized")
        files = manifest.get("files")
        payloads = json.loads("".join(parser.islands["capsule-files"]))
        if not isinstance(files, list) or not isinstance(payloads, list) or len(files) != len(payloads):
            raise CarryProofError("Payload count does not match the manifest")
        seen: set[str] = set()
        for entry, payload in zip(files, payloads, strict=True):
            if not isinstance(entry, dict) or not isinstance(payload, dict):
                raise CarryProofError("Invalid capsule file entry")
            name = entry.get("path")
            if not isinstance(name, str) or not name or archive_name_is_unsafe(name) or name in seen:
                raise CarryProofError("Unsafe or duplicate capsule path")
            seen.add(name)
            if payload.get("path") != name or not isinstance(payload.get("data"), str):
                raise CarryProofError("Payload order does not match the manifest")
            size = entry.get("size")
            expected = entry.get("sha256")
            if type(size) is not int or size < 0 or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise CarryProofError("Invalid payload size or hash")
            decoded = base64.b64decode(payload["data"], validate=True)
            checked += 1
            if len(decoded) != size or not hmac.compare_digest(hashlib.sha256(decoded).hexdigest(), expected):
                failures.append(f"Payload size or hash mismatch: {name}")
    except (CarryProofError, OSError, ValueError, RecursionError) as exc:
        failures.append(str(exc))
    return {
        "ok": not failures,
        "checked": checked,
        "failures": failures,
        "seal": seal,
        "sha256": actual_sha256,
        "trusted_hash_checked": expected_sha256 is not None,
    }


def generate_report_html(
    original: Report, prepared: Report | None = None, *, include_generated: bool = True
) -> bytes:
    encoded = json.dumps(
        report_payload(original, prepared, include_generated=include_generated), ensure_ascii=False
    ).replace("<", "\\u003c")
    document = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>CarryProof report</title>
<style>
:root{--ink:#171b1f;--muted:#667078;--line:#d8dddf;--paper:#f5f6f3;--surface:#fff;--teal:#087f76;--teal-soft:#dcefeb;--orange:#b9582b;--orange-soft:#f7e5d8;--red:#b4232f;--red-soft:#f8dde0;--yellow:#8c6900;--yellow-soft:#f6edc8;--blue:#315b85;--shadow:0 10px 30px rgba(23,27,31,.09);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:var(--paper)}
*{box-sizing:border-box}body{margin:0;min-width:0}button,input{font:inherit;letter-spacing:0}button{cursor:pointer}.topbar{height:72px;border-bottom:1px solid var(--line);background:var(--surface);display:flex;align-items:center;justify-content:space-between;padding:0 clamp(18px,4vw,54px);position:sticky;top:0;z-index:10}.brand{display:flex;align-items:center;gap:12px}.mark{width:38px;height:38px;display:grid;place-items:center;background:var(--ink);color:#fff;font-weight:800;font-size:13px;border-radius:6px}.brand strong{display:block;font-size:17px}.brand small{color:var(--muted);font-size:12px}.status{font-size:12px;font-weight:800;text-transform:uppercase;border-radius:999px;padding:7px 11px;background:var(--teal-soft);color:var(--teal)}.status.blocked{background:var(--red-soft);color:var(--red)}.status.review{background:var(--orange-soft);color:var(--orange)}.status.caution{background:var(--yellow-soft);color:var(--yellow)}
.shell{max-width:1320px;margin:0 auto;padding:34px clamp(18px,4vw,54px) 64px}.headline{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:26px}.headline h1{font-size:30px;line-height:1.05;margin:0 0 8px;letter-spacing:0}.headline p{margin:0;color:var(--muted);max-width:720px}.mode-switch{display:flex;border:1px solid var(--line);border-radius:6px;background:var(--surface);padding:3px;flex:0 0 auto}.mode-switch button{border:0;background:transparent;padding:8px 12px;border-radius:4px;color:var(--muted);font-weight:700}.mode-switch button.active{background:var(--ink);color:#fff}.summary{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line);background:var(--surface);border-radius:7px;overflow:hidden;margin-bottom:28px}.metric{padding:18px;border-right:1px solid var(--line);min-width:0}.metric:last-child{border:0}.metric span{display:block;color:var(--muted);font-size:12px;margin-bottom:7px}.metric strong{font-size:25px;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.risk-meter{height:5px;background:#e8ebec;margin-top:9px;border-radius:999px;overflow:hidden}.risk-meter i{display:block;height:100%;background:var(--teal)}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:20px}.tabs button{border:0;background:transparent;padding:11px 14px;color:var(--muted);font-weight:700;border-bottom:3px solid transparent}.tabs button.active{color:var(--ink);border-bottom-color:var(--teal)}.view[hidden]{display:none}.section-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:4px 0 14px}.section-head h2{font-size:18px;margin:0}.section-head p{color:var(--muted);margin:0;font-size:13px}.search{width:min(360px,100%);border:1px solid var(--line);border-radius:6px;background:var(--surface);padding:9px 11px;outline:none}.search:focus{border-color:var(--teal);box-shadow:0 0 0 3px var(--teal-soft)}
.severity-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-bottom:22px}.severity{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:13px}.severity b{font-size:22px;display:block}.severity small{color:var(--muted);text-transform:capitalize}.finding-list{display:grid;gap:8px}.finding{display:grid;grid-template-columns:88px minmax(180px,1fr) minmax(220px,1.4fr);gap:15px;align-items:start;background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:5px;padding:14px}.finding.high{border-left-color:var(--orange)}.finding.critical{border-left-color:var(--red)}.finding.medium{border-left-color:var(--yellow)}.finding .sev{text-transform:uppercase;font-size:11px;font-weight:900;color:var(--muted)}.finding h3{font-size:14px;margin:0 0 4px;overflow-wrap:anywhere}.finding p{margin:0;color:var(--muted);font-size:13px;line-height:1.45;overflow-wrap:anywhere}.finding code{font-size:11px;color:var(--blue);display:block;margin-top:5px;overflow-wrap:anywhere}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:6px;background:var(--surface)}table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;padding:11px 13px;border-bottom:1px solid var(--line);font-size:13px}th{position:sticky;top:0;background:#eef1ef;color:var(--muted);font-size:11px;text-transform:uppercase}tr:last-child td{border-bottom:0}.path{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.tag{display:inline-block;background:#edf1f2;border-radius:4px;padding:3px 6px;font-size:11px}.cleaning{color:var(--teal);font-size:12px}.empty{background:var(--surface);border:1px dashed var(--line);border-radius:6px;padding:36px;text-align:center;color:var(--muted)}.duplicate{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:8px}.duplicate strong{display:block;margin-bottom:7px}.duplicate code{display:block;color:var(--muted);font-size:12px;padding:2px 0;overflow-wrap:anywhere}.footer{margin-top:38px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12px;display:flex;justify-content:space-between;gap:20px}
@media(max-width:850px){.summary{grid-template-columns:repeat(2,1fr)}.metric{border-bottom:1px solid var(--line)}.headline{align-items:flex-start;flex-direction:column}.finding{grid-template-columns:72px 1fr}.finding>div:last-child{grid-column:2}.severity-grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:520px){.topbar{height:64px}.brand small{display:none}.shell{padding-top:22px}.summary{grid-template-columns:1fr 1fr}.severity-grid{grid-template-columns:1fr 1fr}.finding{grid-template-columns:1fr}.finding>div:last-child{grid-column:auto}.footer{flex-direction:column}.mode-switch{width:100%}.mode-switch button{flex:1}}
</style>
</head>
<body>
<header class="topbar"><div class="brand"><span class="mark">CP</span><div><strong>CarryProof</strong><small>local file inspection</small></div></div><span id="status" class="status">loading</span></header>
<main class="shell">
  <section class="headline"><div><h1 id="title">Inspection report</h1><p id="subtitle"></p></div><div id="modeSwitch" class="mode-switch" hidden><button data-mode="original" class="active">Original</button><button data-mode="prepared">Prepared</button></div></section>
  <section id="summary" class="summary"></section>
  <nav class="tabs" aria-label="Report views"><button data-view="findings" class="active">Findings</button><button data-view="files">Files</button><button data-view="duplicates">Duplicates</button></nav>
  <section id="findings" class="view"><div class="section-head"><div><h2>Findings</h2><p id="findingCaption"></p></div><input id="findingSearch" class="search" type="search" placeholder="Filter findings" aria-label="Filter findings"></div><div id="severityGrid" class="severity-grid"></div><div id="findingList" class="finding-list"></div></section>
  <section id="files" class="view" hidden><div class="section-head"><div><h2>File inventory</h2><p>SHA-256, detected type, metadata and cleaning actions.</p></div><input id="fileSearch" class="search" type="search" placeholder="Filter files" aria-label="Filter files"></div><div class="table-wrap"><table><thead><tr><th>Path</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Metadata / action</th></tr></thead><tbody id="fileRows"></tbody></table></div></section>
  <section id="duplicates" class="view" hidden><div class="section-head"><div><h2>Duplicate groups</h2><p>Byte-identical files, grouped by SHA-256.</p></div></div><div id="duplicateList"></div></section>
  <footer class="footer"><span id="generated"></span><span>Not a malware verdict.</span></footer>
</main>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
const $ = id => document.getElementById(id);
const payload = JSON.parse($('report-data').textContent);
let mode = 'original';
let report = payload[mode];

function esc(value) {
  const entities = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
  return String(value ?? '').replace(/[&<>"']/g, character => entities[character]);
}

function bytes(size) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let unit = 0;
  let value = Number(size) || 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return value.toFixed(unit ? 1 : 0) + ' ' + units[unit];
}

function render() {
  report = payload[mode];
  const summary = report.summary;
  const label = mode === 'original' ? 'Original inspection' : 'Prepared-copy verification';
  $('status').textContent = summary.status;
  $('status').className = 'status ' + summary.status;
  $('title').textContent = report.source.name;
  $('subtitle').textContent = `${label} - ${summary.files} files inspected`;

  const riskMeter = `<div class="risk-meter"><i style="width:${summary.risk_score}%"></i></div>`;
  const metrics = [
    ['Heuristic score', summary.risk_score + '/100', riskMeter],
    ['Files', summary.files, ''],
    ['Total size', bytes(summary.bytes), ''],
    ['Findings', summary.findings, ''],
    ['Reclaimable', bytes(summary.reclaimable_bytes), ''],
  ];
  $('summary').innerHTML = metrics.map(([name, value, extra]) =>
    `<div class="metric"><span>${name}</span><strong>${value}</strong>${extra}</div>`
  ).join('');

  renderFindings();
  renderFiles();
  renderDuplicates();
  $('generated').textContent = 'Report generated ' + (report.generated_utc || 'deterministically');
}

function renderFindings() {
  const query = $('findingSearch').value.toLowerCase();
  const findings = report.findings.filter(finding =>
    JSON.stringify(finding).toLowerCase().includes(query)
  );
  const counts = report.summary.severity_counts;
  $('severityGrid').innerHTML = ['critical', 'high', 'medium', 'low', 'info'].map(severity =>
    `<div class="severity"><b>${counts[severity]}</b><small>${severity}</small></div>`
  ).join('');
  $('findingCaption').textContent = `${findings.length} of ${report.findings.length} shown`;

  $('findingList').innerHTML = findings.length ? findings.map(finding => {
    const detail = finding.detail || finding.remediation || 'No additional detail.';
    const action = finding.remediation
      ? `<p><strong>Action:</strong> ${esc(finding.remediation)}</p>`
      : '';
    return `<article class="finding ${esc(finding.severity)}">
      <div class="sev">${esc(finding.severity)}</div>
      <div>
        <h3>${esc(finding.message)}</h3>
        <p>${esc(finding.location)}</p>
        <code>${esc(finding.code)}</code>
      </div>
      <div><p>${esc(detail)}</p>${action}</div>
    </article>`;
  }).join('') : '<div class="empty">No findings match this filter.</div>';
}

function renderFiles() {
  const query = $('fileSearch').value.toLowerCase();
  const files = report.files.filter(file => JSON.stringify(file).toLowerCase().includes(query));
  $('fileRows').innerHTML = files.map(file => {
    const metadata = file.metadata?.length
      ? `<div>${file.metadata.map(esc).join(', ')}</div>`
      : '';
    const cleaning = file.cleaning?.length
      ? `<div class="cleaning">${file.cleaning.map(esc).join('; ')}</div>`
      : '';
    const duplicate = file.duplicate_of
      ? `<div>duplicate of ${esc(file.duplicate_of)}</div>`
      : '';
    return `<tr>
      <td class="path">${esc(file.path)}</td>
      <td><span class="tag">${esc(file.type)}</span></td>
      <td>${bytes(file.size)}</td>
      <td class="path" title="${esc(file.sha256)}">${esc(file.sha256.slice(0, 12))}...</td>
      <td>${metadata}${cleaning}${duplicate}</td>
    </tr>`;
  }).join('');
}

function renderDuplicates() {
  const groups = report.duplicates || [];
  $('duplicateList').innerHTML = groups.length ? groups.map(group => {
    const paths = group.paths.map(path => `<code>${esc(path)}</code>`).join('');
    return `<article class="duplicate">
      <strong>${group.paths.length} copies - ${bytes(group.reclaimable_bytes)} reclaimable</strong>
      ${paths}
    </article>`;
  }).join('') : '<div class="empty">No byte-identical duplicate files found.</div>';
}

const viewButtons = document.querySelectorAll('[data-view]');
viewButtons.forEach(button => button.addEventListener('click', () => {
  viewButtons.forEach(other => other.classList.toggle('active', other === button));
  document.querySelectorAll('.view').forEach(view => {
    view.hidden = view.id !== button.dataset.view;
  });
}));
$('findingSearch').addEventListener('input', renderFindings);
$('fileSearch').addEventListener('input', renderFiles);

if (payload.prepared) {
  const modeSwitch = $('modeSwitch');
  const modeButtons = modeSwitch.querySelectorAll('button');
  modeSwitch.hidden = false;
  modeButtons.forEach(button => button.addEventListener('click', () => {
    mode = button.dataset.mode;
    modeButtons.forEach(other => other.classList.toggle('active', other === button));
    render();
  }));
}
render();
</script>
</body></html>'''
    return document.replace("__REPORT_DATA__", encoded).encode("utf-8")


PORTAL_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>CarryProof portal</title>
<style nonce="__NONCE__">
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;letter-spacing:0;color:#171b1f;background:#f4f6f4;--line:#d7dddc;--muted:#69747a;--teal:#087f76;--teal2:#dcefeb;--orange:#b9582b;--red:#b4232f;--red2:#f8dde0;--yellow:#8c6900;--surface:#fff}*{box-sizing:border-box}body{margin:0;min-width:0}button,input{font:inherit;letter-spacing:0}button{cursor:pointer}.top{height:68px;background:var(--surface);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 clamp(16px,4vw,48px)}.brand{display:flex;align-items:center;gap:11px}.mark{width:36px;height:36px;border-radius:6px;display:grid;place-items:center;background:#171b1f;color:#fff;font-size:12px;font-weight:900}.brand strong{display:block}.brand small{display:block;color:var(--muted);font-size:11px}.pill{font-size:11px;font-weight:800;color:var(--teal);background:var(--teal2);padding:6px 9px;border-radius:999px}.shell{max-width:1120px;margin:auto;padding:30px clamp(16px,4vw,48px) 60px}.showcase{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(320px,.8fr);gap:34px;padding:8px 0 30px;border-bottom:1px solid var(--line);margin-bottom:26px}.showcase[hidden]{display:none}.showcase .eyebrow{color:var(--teal);font-size:11px;font-weight:900;text-transform:uppercase;margin:0 0 8px}.showcase h1{font-size:32px;line-height:1.03;margin:0 0 12px}.showcase p{color:var(--muted);line-height:1.55;margin:0}.showcase-actions{display:flex;gap:8px;margin-top:18px;flex-wrap:wrap}.evidence{background:var(--surface);border:1px solid var(--line);border-radius:7px;overflow:hidden;display:grid;grid-template-columns:1fr 1fr}.evidence div{padding:16px;border-bottom:1px solid var(--line)}.evidence div:nth-child(odd){border-right:1px solid var(--line)}.evidence div:nth-last-child(-n+2){border-bottom:0}.evidence span{display:block;color:var(--muted);font-size:10px;font-weight:900;text-transform:uppercase;margin-bottom:7px}.evidence strong{font-size:23px}.evidence .good{color:var(--teal)}.artifact-title{display:flex;align-items:end;justify-content:space-between;gap:14px;margin:0 0 12px}.artifact-title h2{font-size:18px;margin:0}.artifact-title p{font-size:12px;color:var(--muted);margin:3px 0 0}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:12px}.crumbs{display:flex;gap:5px;align-items:center;min-width:0}.crumbs button{border:0;background:transparent;color:var(--teal);padding:5px;font-weight:700}.actions{display:flex;gap:8px}.action{border:1px solid var(--line);background:var(--surface);border-radius:6px;padding:8px 11px;font-weight:700;color:#273137;text-decoration:none}.action.primary{background:#171b1f;color:#fff;border-color:#171b1f}.panel{background:var(--surface);border:1px solid var(--line);border-radius:7px;overflow:hidden}.row{display:grid;grid-template-columns:minmax(180px,1fr) 130px 170px 92px;align-items:center;gap:12px;padding:12px 14px;border-bottom:1px solid var(--line)}.row:last-child{border:0}.row.head{background:#edf1ef;text-transform:uppercase;font-size:10px;color:var(--muted);font-weight:800}.name{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.name button{border:0;background:transparent;padding:0;color:#171b1f;font-weight:700;text-align:left}.meta{color:var(--muted);font-size:12px}.download{color:var(--teal);font-weight:800;text-decoration:none;font-size:12px}.empty{padding:54px 20px;text-align:center;color:var(--muted)}.login{position:fixed;inset:0;background:#f4f6f4;display:grid;place-items:center;padding:20px;z-index:20}.login[hidden]{display:none}.login-box{width:min(440px,100%);background:var(--surface);border:1px solid var(--line);border-radius:7px;box-shadow:0 18px 50px rgba(23,27,31,.12);padding:28px}.login-box h1{font-size:28px;margin:18px 0 7px}.login-box p{color:var(--muted);margin:0 0 18px}.demo-access{border:1px solid #e1c96a;background:#fff9df;border-radius:6px;padding:12px;margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;gap:12px}.demo-access[hidden]{display:none}.demo-access span{display:block;color:var(--yellow);font-size:10px;text-transform:uppercase;font-weight:900}.demo-access strong{font:18px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:0}.demo-access .demo-fill{width:auto;margin:0;background:transparent;color:#171b1f;border:1px solid #d7c16a;padding:7px 9px;flex:0 0 auto}.login-box input{width:100%;border:1px solid var(--line);border-radius:6px;padding:12px;font-size:19px;letter-spacing:0;text-align:center}.login-box button{width:100%;border:0;background:#171b1f;color:#fff;border-radius:6px;padding:12px;margin-top:10px;font-weight:800}.error{color:var(--red);font-size:12px;min-height:18px;margin-top:8px}.foot{color:var(--muted);font-size:11px;margin-top:18px;display:flex;justify-content:space-between}.toast{position:fixed;right:18px;bottom:18px;background:#171b1f;color:#fff;padding:11px 14px;border-radius:6px;font-size:12px;opacity:0;transform:translateY(8px);transition:.2s;pointer-events:none}.toast.show{opacity:1;transform:none}@media(max-width:760px){.showcase{grid-template-columns:1fr;gap:22px}.row{grid-template-columns:minmax(140px,1fr) 80px 72px}.row>*:nth-child(3){display:none}.brand small{display:none}.toolbar,.artifact-title{align-items:flex-start;flex-direction:column}.actions,.showcase-actions{width:100%}.action{flex:1;text-align:center}.row.head{font-size:9px}}@media(max-width:430px){.row{grid-template-columns:minmax(120px,1fr) 70px}.row>*:nth-child(2){display:none}.showcase-actions{flex-direction:column}.evidence strong{font-size:19px}.demo-access{align-items:flex-start;flex-wrap:wrap}}
.brand{min-width:0}.brand .mark{flex:0 0 auto}.brand>div{min-width:0}.brand strong{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
</style></head><body>
<header class="top"><div class="brand"><span class="mark">CP</span><div><strong>CarryProof</strong><small id="shareName">private local portal</small></div></div><span class="pill">read only</span></header>
<main class="shell">
  <section id="showcase" class="showcase" hidden>
    <div>
      <p class="eyebrow">Prepared file handoff</p>
      <h1 id="showcaseTitle">CarryProof handoff</h1>
      <p>Prepared files, recorded changes, and integrity checks. Scores are heuristic; prepared copies can retain findings.</p>
      <div class="showcase-actions">
        <a id="capsuleLink" class="action primary" href="/capsule" hidden>Open offline capsule</a>
        <a id="reportLink" class="action" href="/report" hidden>Inspect before / after</a>
        <a id="bundleLink" class="action" hidden>Download ZIP bundle</a>
      </div>
    </div>
    <div id="evidence" class="evidence"></div>
  </section>
  <div class="artifact-title">
    <div><h2>Handoff files</h2><p>Prepared copies, manifests, bundle, and recovery data.</p></div>
  </div>
  <div class="toolbar">
    <div id="crumbs" class="crumbs"></div>
    <div class="actions"><button id="refresh" class="action">Refresh</button></div>
  </div>
  <section class="panel">
    <div class="row head"><span>Name</span><span>Size</span><span>Modified</span><span>Action</span></div>
    <div id="rows"></div>
  </section>
  <div class="foot"><span id="count"></span><span>Read-only portal. Nothing is uploaded.</span></div>
</main>
<section id="login" class="login"><form id="loginForm" class="login-box"><span class="mark">CP</span><h1>Open this handoff</h1><p>Enter the temporary access code shown by the sender.</p><div id="demoAccess" class="demo-access" hidden><div><span>Judge demo code</span><strong id="demoCode"></strong></div><button id="fillDemo" class="demo-fill" type="button">Use code</button></div><input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="32" aria-label="Access code" autofocus><button type="submit">Unlock handoff</button><div id="loginError" class="error"></div></form></section><div id="toast" class="toast"></div>
<script nonce="__NONCE__">
const demo = __DEMO_DATA__;
const $ = id => document.getElementById(id);
let currentPath = '';

function esc(value) {
  const entities = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
  return String(value ?? '').replace(/[&<>"']/g, character => entities[character]);
}

function bytes(size) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let unit = 0;
  let value = Number(size) || 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return value.toFixed(unit ? 1 : 0) + ' ' + units[unit];
}

async function api(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    $('login').hidden = false;
    throw new Error('locked');
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || 'Request failed');
  return body;
}

function toast(message) {
  $('toast').textContent = message;
  $('toast').classList.add('show');
  setTimeout(() => $('toast').classList.remove('show'), 1800);
}

function renderEvidence(info) {
  const evidence = info.evidence;
  $('showcase').hidden = !evidence;
  if (!evidence) return;

  const metrics = [
    ['Heuristic score', evidence.before_risk + ' -> ' + evidence.prepared_risk, ''],
    ['Fewer findings', evidence.removed_findings, ''],
    ['Prepared files', evidence.files, ''],
    ['Recovery data', info.recovery_name ? 'ready' : 'not created', info.recovery_name ? 'good' : ''],
  ];
  $('evidence').innerHTML = metrics.map(([name, value, className]) =>
    `<div><span>${name}</span><strong class="${className}">${value}</strong></div>`
  ).join('');
  $('capsuleLink').hidden = !info.has_capsule;
  $('reportLink').hidden = !info.has_report;
  $('bundleLink').hidden = !info.bundle_name;
  if (info.bundle_name) {
    $('bundleLink').href = '/file?path=' + encodeURIComponent(info.bundle_name);
  }
}

async function boot() {
  try {
    const info = await api('/api/info');
    $('login').hidden = true;
    $('shareName').textContent = info.name;
    renderEvidence(info);
    await list('');
  } catch (error) {
    if (error.message !== 'locked') toast(error.message);
  }
}

async function list(path) {
  currentPath = path;
  const data = await api('/api/list?path=' + encodeURIComponent(path));
  const parts = path ? path.split('/') : [];
  $('crumbs').innerHTML = '<button data-path="">Root</button>' + parts.map((part, index) => {
    const parentPath = parts.slice(0, index + 1).join('/');
    return `<span>/</span><button data-path="${esc(parentPath)}">${esc(part)}</button>`;
  }).join('');
  $('crumbs').querySelectorAll('button').forEach(button => {
    button.onclick = () => list(button.dataset.path);
  });

  $('rows').innerHTML = data.entries.length ? data.entries.map(entry => {
    const name = entry.directory
      ? `<button data-dir="${esc(entry.path)}">${esc(entry.name)}/</button>`
      : `<span>${esc(entry.name)}</span>`;
    const download = entry.directory
      ? ''
      : `<a class="download" href="/file?path=${encodeURIComponent(entry.path)}">Download</a>`;
    return `<div class="row">
      <div class="name">${name}</div>
      <span class="meta">${entry.directory ? 'folder' : bytes(entry.size)}</span>
      <span class="meta">${esc(entry.modified)}</span>
      <span>${download}</span>
    </div>`;
  }).join('') : '<div class="empty">This folder is empty.</div>';
  $('rows').querySelectorAll('[data-dir]').forEach(button => {
    button.onclick = () => list(button.dataset.dir);
  });
  $('count').textContent = data.entries.length + ' item' + (data.entries.length === 1 ? '' : 's');
}

$('loginForm').onsubmit = async event => {
  event.preventDefault();
  $('loginError').textContent = '';
  try {
    await api('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code: $('code').value}),
    });
    $('code').value = '';
    await boot();
  } catch (error) {
    $('loginError').textContent = error.message === 'locked'
      ? 'Incorrect or rate-limited access code.'
      : error.message;
  }
};
$('refresh').onclick = () => list(currentPath).catch(error => toast(error.message));

if (demo.enabled) {
  $('demoAccess').hidden = false;
  $('demoCode').textContent = demo.code.replace(/(.{4})/g, '$1 ').trim();
  $('fillDemo').onclick = () => {
    $('code').value = demo.code;
    $('code').focus();
  };
}
boot();
</script></body></html>'''


def parse_http_range(value: str, size: int) -> tuple[int, int]:
    if not value.startswith("bytes=") or "," in value:
        raise CarryProofError("Only one byte range is supported")
    spec = value[6:].strip()
    if "-" not in spec:
        raise CarryProofError("Malformed byte range")
    first, last = spec.split("-", 1)
    if first:
        start = int(first)
        end = int(last) if last else size - 1
    else:
        suffix = int(last)
        if suffix <= 0:
            raise CarryProofError("Malformed suffix range")
        start = max(0, size - suffix)
        end = size - 1
    if start < 0 or start >= size or end < start:
        raise CarryProofError("Range is outside the file")
    return start, min(end, size - 1)


@dataclass
class PortalSession:
    created: float
    last_seen: float


class PortalState:
    def __init__(self, root: Path, code: str, session_seconds: int = 12 * 3600, *, demo: bool = False):
        self.root = root.resolve()
        self.base = self.root if self.root.is_dir() else self.root.parent
        self.code = self.normalize_code(code)
        self.demo = demo
        self.session_seconds = session_seconds
        self.sessions: dict[str, PortalSession] = {}
        self.failures: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.RLock()
        self.started = time.time()

    def report_path(self, name: str) -> Path | None:
        if not self.root.is_dir():
            return None
        with contextlib.suppress(CarryProofError, OSError):
            candidate = self.resolve(name)
            return candidate if candidate.is_file() else None
        return None

    def capsule_path(self) -> Path | None:
        if not self.root.is_dir():
            return None
        candidates = sorted(self.root.glob("*.carryproof.html"), key=lambda item: item.name.casefold())
        for candidate in candidates:
            with contextlib.suppress(CarryProofError, OSError):
                resolved = self.resolve(candidate.name)
                if resolved.is_file():
                    return resolved
        return None

    def artifact_name(self, suffix: str) -> str | None:
        if not self.root.is_dir():
            return self.root.name if self.root.name.endswith(suffix) else None
        candidates = sorted(
            (path for path in self.root.iterdir() if path.is_file() and path.name.endswith(suffix)),
            key=lambda item: item.name.casefold(),
        )
        return candidates[0].name if candidates else None

    def evidence(self) -> dict[str, Any] | None:
        report_path = self.report_path("carryproof-report.json")
        if report_path is None:
            return None
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            original = payload["original"]["summary"]
            prepared = payload.get("prepared", payload["original"])["summary"]
            capsule_meta = self.report_path("carryproof-capsule.json")
            capsule = json.loads(capsule_meta.read_text(encoding="utf-8")) if capsule_meta else {}
            return {
                "before_risk": int(original["risk_score"]),
                "prepared_risk": int(prepared["risk_score"]),
                "removed_findings": max(0, int(original["findings"]) - int(prepared["findings"])),
                "files": int(prepared["files"]),
                "capsule_seal": str(capsule.get("seal", "")),
            }
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def normalize_code(value: str) -> str:
        return re.sub(r"[\s-]+", "", value)

    def resolve(self, raw: str) -> Path:
        raw = raw.replace("\\", "/").strip("/")
        if self.root.is_file():
            if raw not in ("", self.root.name):
                raise CarryProofError("Path is outside the shared file")
            return self.root
        if raw:
            relative = safe_relative_path(raw)
            candidate = self.root.joinpath(*relative.parts).resolve()
        else:
            candidate = self.root
        try:
            common = Path(os.path.commonpath([str(self.root), str(candidate)]))
        except ValueError as exc:
            raise CarryProofError("Path is outside the shared folder") from exc
        if common != self.root:
            raise CarryProofError("Path is outside the shared folder")
        return candidate

    def login_allowed(self, address: str) -> bool:
        now = time.time()
        with self.lock:
            queue = self.failures[address]
            while queue and queue[0] < now - 60:
                queue.popleft()
            return len(queue) < 6

    def issue_session(self, address: str, candidate: str) -> str | None:
        if not self.login_allowed(address):
            return None
        if not hmac.compare_digest(self.normalize_code(candidate), self.code):
            with self.lock:
                self.failures[address].append(time.time())
            return None
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self.sessions[token] = PortalSession(now, now)
            self.failures.pop(address, None)
        return token

    def authenticated(self, token: str | None) -> bool:
        if not token:
            return False
        now = time.time()
        with self.lock:
            session = self.sessions.get(token)
            if session is None or session.last_seen < now - self.session_seconds:
                self.sessions.pop(token, None)
                return False
            session.last_seen = now
            return True


class CarryProofServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: PortalState):
        self.state = state
        super().__init__(address, CarryProofHandler)


class CarryProofHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CarryProof"
    sys_version = ""

    @property
    def app(self) -> PortalState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _headers(self, *, cache: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "private, max-age=60" if cache else "no-store")

    def _bytes(self, status: int, data: bytes, content_type: str, *, head: bool = False) -> None:
        self.send_response(status)
        self._headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def _json(self, status: int, value: Any, *, head: bool = False) -> None:
        self._bytes(status, deterministic_json(value), "application/json; charset=utf-8", head=head)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _token(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        with contextlib.suppress(cookies.CookieError):
            jar.load(raw)
        morsel = jar.get("carryproof_session")
        return morsel.value if morsel else None

    def _require_auth(self) -> bool:
        if self.app.authenticated(self._token()):
            return True
        self._error(HTTPStatus.UNAUTHORIZED, "Authentication required")
        return False

    def _read_json(self, maximum: int = 64 * 1024) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise CarryProofError("Invalid Content-Length") from exc
        if length <= 0 or length > maximum:
            raise CarryProofError("Request body size is invalid")
        try:
            value = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise CarryProofError("Malformed JSON request") from exc
        if not isinstance(value, dict):
            raise CarryProofError("JSON request must be an object")
        return value

    def do_POST(self) -> None:
        route = urllib.parse.urlsplit(self.path).path
        if route != "/api/login":
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            body = self._read_json()
            token = self.app.issue_session(self.client_address[0], str(body.get("code", "")))
            if token is None:
                self._error(HTTPStatus.UNAUTHORIZED, "Incorrect or rate-limited access code")
                return
            self.send_response(HTTPStatus.OK)
            self._headers()
            self.send_header("Set-Cookie", f"carryproof_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={self.app.session_seconds}")
            data = b'{"ok":true}\n'
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except CarryProofError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def do_HEAD(self) -> None:
        self._dispatch_get(head=True)

    def do_GET(self) -> None:
        self._dispatch_get(head=False)

    def _dispatch_get(self, *, head: bool) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if route == "/":
                nonce = secrets.token_urlsafe(18)
                demo_data = json.dumps(
                    {"enabled": self.app.demo, "code": self.app.code if self.app.demo else ""},
                    separators=(",", ":"),
                ).replace("<", "\\u003c")
                data = PORTAL_HTML.replace("__NONCE__", nonce).replace("__DEMO_DATA__", demo_data).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self._headers()
                self.send_header("Content-Security-Policy", f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if not head:
                    self.wfile.write(data)
                return
            if route == "/healthz":
                self._json(HTTPStatus.OK, {"ok": True, "service": APP_NAME}, head=head)
                return
            if not self._require_auth():
                return
            if route == "/api/info":
                report_path = self.app.report_path("carryproof-report.html")
                capsule_path = self.app.capsule_path()
                self._json(
                    HTTPStatus.OK,
                    {
                        "name": self.app.root.name,
                        "version": VERSION,
                        "has_report": report_path is not None,
                        "has_capsule": capsule_path is not None,
                        "capsule_name": capsule_path.name if capsule_path else None,
                        "bundle_name": self.app.artifact_name(".carryproof.zip"),
                        "recovery_name": self.app.artifact_name(".carryproof.zip.cproof"),
                        "evidence": self.app.evidence(),
                        "demo": self.app.demo,
                        "uptime_seconds": int(time.time() - self.app.started),
                    },
                    head=head,
                )
                return
            if route == "/api/list":
                self._serve_list(query.get("path", [""])[0], head=head)
                return
            if route == "/api/hash":
                path = self.app.resolve(query.get("path", [""])[0])
                if not path.is_file():
                    raise CarryProofError("Path is not a file")
                self._json(HTTPStatus.OK, {"path": path.name, "sha256": sha256_file(path)}, head=head)
                return
            if route == "/api/report":
                report_path = self.app.report_path("carryproof-report.json")
                if report_path is None:
                    self._error(HTTPStatus.NOT_FOUND, "No report is available")
                    return
                self._bytes(HTTPStatus.OK, report_path.read_bytes(), "application/json; charset=utf-8", head=head)
                return
            if route == "/report":
                report_path = self.app.report_path("carryproof-report.html")
                if report_path is None:
                    self._error(HTTPStatus.NOT_FOUND, "No report is available")
                    return
                data = report_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self._headers()
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if not head:
                    self.wfile.write(data)
                return
            if route == "/capsule":
                capsule_path = self.app.capsule_path()
                if capsule_path is None:
                    self._error(HTTPStatus.NOT_FOUND, "No offline capsule is available")
                    return
                size = capsule_path.stat().st_size
                self.send_response(HTTPStatus.OK)
                self._headers()
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; media-src blob:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(size))
                self.end_headers()
                if not head:
                    with capsule_path.open("rb") as source:
                        shutil.copyfileobj(source, self.wfile, COPY_BUFFER)
                return
            if route == "/file":
                self._serve_file(query.get("path", [""])[0], head=head)
                return
            self._error(HTTPStatus.NOT_FOUND, "Not found")
        except (CarryProofError, OSError, ValueError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _serve_list(self, raw: str, *, head: bool) -> None:
        path = self.app.resolve(raw)
        if self.app.root.is_file():
            paths = [self.app.root]
            parent_raw = ""
        else:
            if not path.is_dir():
                raise CarryProofError("Path is not a directory")
            paths = sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.casefold()))
            parent_raw = raw.strip("/")
        entries: list[dict[str, Any]] = []
        for item in paths:
            with contextlib.suppress(OSError, CarryProofError):
                resolved = item.resolve()
                if self.app.root.is_dir() and Path(os.path.commonpath([str(self.app.root), str(resolved)])) != self.app.root:
                    continue
                rel = item.name if self.app.root.is_file() else item.relative_to(self.app.root).as_posix()
                info = item.stat()
                entries.append(
                    {
                        "name": item.name,
                        "path": rel,
                        "directory": item.is_dir(),
                        "size": 0 if item.is_dir() else info.st_size,
                        "modified": dt.datetime.fromtimestamp(info.st_mtime).astimezone().strftime("%Y-%m-%d %H:%M"),
                    }
                )
        self._json(HTTPStatus.OK, {"path": parent_raw, "entries": entries}, head=head)

    def _serve_file(self, raw: str, *, head: bool) -> None:
        path = self.app.resolve(raw)
        if not path.is_file():
            raise CarryProofError("Path is not a file")
        size = path.stat().st_size
        start, end = 0, max(0, size - 1)
        status = HTTPStatus.OK
        range_header = self.headers.get("Range")
        if range_header and size:
            start, end = parse_http_range(range_header, size)
            status = HTTPStatus.PARTIAL_CONTENT
        length = 0 if size == 0 else end - start + 1
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        fallback = re.sub(r"[^A-Za-z0-9._-]", "_", path.name) or "download"
        encoded = urllib.parse.quote(path.name, safe="")
        self.send_response(status)
        self._headers(cache=True)
        self.send_header("Content-Type", mime)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Disposition", f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
        self.send_header("Content-Length", str(length))
        if status == HTTPStatus.PARTIAL_CONTENT:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if head or length == 0:
            return
        with path.open("rb") as handle:
            handle.seek(start)
            remaining = length
            while remaining:
                block = handle.read(min(COPY_BUFFER, remaining))
                if not block:
                    break
                self.wfile.write(block)
                remaining -= len(block)


def network_urls(host: str, port: int) -> list[str]:
    if host not in {"0.0.0.0", "::", ""}:
        display = f"[{host}]" if ":" in host else host
        return [f"http://{display}:{port}"]
    addresses: set[str] = {"127.0.0.1"}
    with contextlib.suppress(OSError):
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = item[4][0]
            if not address.startswith("127.") and address != "0.0.0.0":
                addresses.add(address)
    return [f"http://{address}:{port}" for address in sorted(addresses, key=lambda value: not value.startswith("127."))]


def run_portal(
    path: Path,
    host: str,
    port: int,
    code: str | None,
    ttl: int,
    open_browser: bool,
    *,
    demo: bool = False,
) -> None:
    path = path.expanduser().resolve()
    if not path.exists():
        raise CarryProofError(f"Path does not exist: {path}")
    access_code = code or f"{secrets.randbelow(100_000_000):08d}"
    state = PortalState(path, access_code, demo=demo)
    server = CarryProofServer((host, port), state)
    actual_port = server.server_address[1]
    urls = network_urls(host, actual_port)
    print("\nCarryProof private portal")
    print(f"Sharing: {path}")
    for url in urls:
        print(f"URL:     {url}")
    display_code = access_code if code else f"{access_code[:4]}-{access_code[4:]}"
    print(f"Code:    {display_code}")
    print("Mode:    read only")
    if demo:
        print("Demo:    access code is disclosed on the login page")
    if ttl:
        print(f"Expires: in {ttl} seconds")
        timer = threading.Timer(ttl, server.shutdown)
        timer.daemon = True
        timer.start()
    if open_browser:
        webbrowser.open(urls[0])
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


class Console:
    def __init__(self) -> None:
        self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def style(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def heading(self, text: str) -> None:
        print(self.style(text, "1;36"))

    def success(self, text: str) -> None:
        print(self.style(text, "1;32"))

    def warning(self, text: str) -> None:
        print(self.style(text, "1;33"))


def report_exit_code(report: Report) -> int:
    return 3 if report.status in {"blocked", "review"} else 0


def print_report_summary(report: Report, console: Console) -> None:
    summary = report.summary()
    console.heading(f"{APP_NAME} inspection: {report.source_name}")
    print(f"Status:       {summary['status'].upper()}")
    print(f"Risk score:   {summary['risk_score']}/100")
    print(f"Files:        {summary['files']:,} ({human_size(summary['bytes'])})")
    print(f"Findings:     {summary['findings']:,}")
    counts = summary["severity_counts"]
    print(f"Severity:     {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium")
    if summary["reclaimable_bytes"]:
        print(f"Duplicates:   {human_size(summary['reclaimable_bytes'])} potentially reclaimable")


def default_output(source: Path) -> Path:
    stem = source.stem if source.is_file() else source.name
    return source.parent / f"{stem}-carryproof"


def validate_output(source: Path, output: Path, overwrite: bool) -> None:
    source = source.resolve()
    output = output.resolve()
    anchor = Path(output.anchor)
    if output == anchor or output == source or source in output.parents or output in source.parents:
        raise CarryProofError("Output must be a separate sibling path, not a drive root, input, child, or parent")
    if output.exists():
        if not overwrite:
            raise CarryProofError(f"Output already exists: {output} (use --overwrite to replace it)")
        if output.is_dir():
            shutil.rmtree(output)
        else:
            output.unlink()


def prepare_workflow(
    source: Path,
    output: Path,
    *,
    overwrite: bool,
    content_scan: bool,
    strip_active: bool,
    parity: bool,
    chunk_size: int,
    stripe_width: int,
) -> dict[str, Any]:
    source = source.expanduser().resolve()
    validate_output(source, output, overwrite)
    output.mkdir(parents=True)
    original = inspect_target(source, content_scan=content_scan)
    cleaned = output / "cleaned"
    clean_target(source, cleaned, original, strip_active=strip_active)
    prepared = inspect_target(cleaned, content_scan=content_scan)
    prepared.source_name = original.source_name
    html_report = generate_report_html(original, prepared)
    write_json(output / "carryproof-report.json", report_payload(original, prepared))
    with atomic_output(output / "carryproof-report.html") as handle:
        handle.write(html_report)
    artifact_stem = source.stem if source.is_file() else source.name
    capsule = output / f"{artifact_stem}.carryproof.html"
    capsule_result = create_capsule(cleaned, capsule, original, prepared)
    write_json(
        output / "carryproof-capsule.json",
        {"seal": capsule_result["seal"], "sha256": capsule_result["sha256"], **capsule_result["manifest"]},
    )
    bundle = output / f"{artifact_stem}.carryproof.zip"
    manifest = make_bundle(
        cleaned, bundle, original,
        generate_report_html(original, prepared, include_generated=False), after=prepared,
    )
    parity_path: Path | None = None
    parity_header: dict[str, Any] | None = None
    if parity:
        parity_path = bundle.with_suffix(bundle.suffix + ".cproof")
        parity_header = create_parity(bundle, parity_path, chunk_size=chunk_size, stripe_width=stripe_width)
    result = {
        "output": str(output),
        "cleaned": str(cleaned),
        "bundle": str(bundle),
        "bundle_sha256": sha256_file(bundle),
        "capsule": str(capsule),
        "capsule_seal": capsule_result["seal"],
        "capsule_sha256": capsule_result["sha256"],
        "parity": str(parity_path) if parity_path else None,
        "original": original,
        "prepared": prepared,
        "manifest": manifest,
        "parity_header": parity_header,
    }
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="carryproof",
        description="Turn risky files into self-verifying offline handoffs using only Python's standard library.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Inspect files without modifying them")
    scan.add_argument("path", type=Path)
    scan.add_argument("-o", "--output", type=Path, default=Path("carryproof-report.json"))
    scan.add_argument("--html", type=Path, default=Path("carryproof-report.html"))
    scan.add_argument("--content", action="store_true", help="Scan visible text for common secrets and identifiers")

    clean = subparsers.add_parser("clean", help="Create sanitized copies while preserving originals")
    clean.add_argument("path", type=Path)
    clean.add_argument("-o", "--output", type=Path)
    clean.add_argument("--strip-active", action="store_true", help="Remove macros, embedded objects, scripts, and external relationships where supported")
    clean.add_argument("--content", action="store_true")
    clean.add_argument("--overwrite", action="store_true")

    prepare = subparsers.add_parser("prepare", help="Create a sanitized, self-verifying capsule, bundle, and recovery data")
    prepare.add_argument("path", type=Path)
    prepare.add_argument("-o", "--output", type=Path)
    prepare.add_argument("--overwrite", action="store_true")
    prepare.add_argument("--no-content", action="store_true", help="Skip visible-text privacy scanning")
    prepare.add_argument("--keep-active", action="store_true", help="Report but do not remove supported active Office/SVG content")
    prepare.add_argument("--no-parity", action="store_true", help="Do not create recovery data for the final bundle")
    prepare.add_argument("--chunk-size", type=parse_size, default=1024 * 1024)
    prepare.add_argument("--stripe-width", type=int, default=8)
    prepare.add_argument("--serve", action="store_true", help="Serve the prepared output after completion")
    prepare.add_argument("--host", default="0.0.0.0")
    prepare.add_argument("--port", type=int, default=0)
    prepare.add_argument("--code")
    prepare.add_argument("--ttl", type=parse_duration, default=0)
    prepare.add_argument("--open", action="store_true", dest="open_browser")
    prepare.add_argument("--demo", action="store_true", help="Show the access code and judge guidance in the portal")

    verify = subparsers.add_parser("verify", help="Independently verify a ZIP bundle or HTML capsule")
    verify.add_argument("artifact", type=Path)
    verify.add_argument("--sha256", help="Expected whole-artifact SHA-256 from a trusted, separate channel")

    protect = subparsers.add_parser("protect", help="Create repair data for any file")
    protect.add_argument("file", type=Path)
    protect.add_argument("-o", "--output", type=Path)
    protect.add_argument("--chunk-size", type=parse_size, default=1024 * 1024)
    protect.add_argument("--stripe-width", type=int, default=8)

    recover = subparsers.add_parser("recover", help="Verify and repair a damaged file using CarryProof parity")
    recover.add_argument("file", type=Path)
    recover.add_argument("parity", type=Path)
    recover.add_argument("-o", "--output", type=Path)

    serve = subparsers.add_parser("serve", help="Share a file or folder through an authenticated read-only browser portal")
    serve.add_argument("path", type=Path)
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=0)
    serve.add_argument("--code")
    serve.add_argument("--ttl", type=parse_duration, default=0)
    serve.add_argument("--open", action="store_true", dest="open_browser")
    serve.add_argument("--demo", action="store_true", help="Show the access code and judge guidance in the portal")

    subparsers.add_parser("doctor", help="Run environment and zero-dependency self-checks")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        if args.command == "scan":
            report = inspect_target(args.path, content_scan=args.content)
            write_json(args.output, report.as_dict())
            with atomic_output(args.html) as handle:
                handle.write(generate_report_html(report))
            print_report_summary(report, console)
            print(f"JSON report:   {args.output.resolve()}")
            print(f"HTML report:   {args.html.resolve()}")
            return report_exit_code(report)
        if args.command == "clean":
            source = args.path.expanduser().resolve()
            output = (args.output or default_output(source)).expanduser().resolve()
            validate_output(source, output, args.overwrite)
            before = inspect_target(source, content_scan=args.content)
            clean_target(source, output, before, strip_active=args.strip_active)
            after = inspect_target(output, content_scan=args.content)
            after.source_name = before.source_name
            write_json(output / "carryproof-report.json", report_payload(before, after))
            with atomic_output(output / "carryproof-report.html") as handle:
                handle.write(generate_report_html(before, after))
            print_report_summary(after, console)
            print(f"Sanitized copy: {output}")
            return report_exit_code(after)
        if args.command == "prepare":
            source = args.path.expanduser().resolve()
            output = (args.output or default_output(source)).expanduser().resolve()
            result = prepare_workflow(
                source,
                output,
                overwrite=args.overwrite,
                content_scan=not args.no_content,
                strip_active=not args.keep_active,
                parity=not args.no_parity,
                chunk_size=args.chunk_size,
                stripe_width=args.stripe_width,
            )
            print_report_summary(result["prepared"], console)
            console.success("\nPreparation complete")
            print(f"Output:        {result['output']}")
            print(f"Bundle:        {result['bundle']}")
            print(f"SHA-256:       {result['bundle_sha256']}")
            print(f"Capsule:       {result['capsule']}")
            print(f"Content seal:  {result['capsule_seal']}")
            print(f"Capsule hash:  {result['capsule_sha256']}")
            if result["parity"]:
                print(f"Recovery data: {result['parity']}")
            print(f"Report:        {Path(result['output']) / 'carryproof-report.html'}")
            if args.serve:
                run_portal(output, args.host, args.port, args.code, args.ttl, args.open_browser, demo=args.demo)
            return report_exit_code(result["prepared"])
        if args.command == "verify":
            artifact = args.artifact.expanduser().resolve()
            if args.sha256 is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", args.sha256):
                raise CarryProofError("Expected SHA-256 must contain exactly 64 hexadecimal characters")
            if artifact.suffix.lower() in {".html", ".htm"}:
                result = verify_capsule(artifact, args.sha256)
            else:
                if args.sha256 is not None and not hmac.compare_digest(sha256_file(artifact), args.sha256.lower()):
                    console.warning("Whole-artifact SHA-256 does not match the trusted value.")
                    return 4
                result = verify_bundle(artifact)
            if result["ok"]:
                console.success(f"Verified {result['checked']} files; all SHA-256 hashes match.")
                if args.sha256:
                    print("Whole-artifact SHA-256 matches the separately supplied value.")
                else:
                    print("Internal integrity only; sender identity and verifier code are not authenticated.")
                return 0
            console.warning("Artifact verification failed:")
            for failure in result["failures"]:
                print(f"- {failure}")
            return 4
        if args.command == "protect":
            source = args.file.expanduser().resolve()
            output = (args.output or source.with_suffix(source.suffix + ".cproof")).expanduser().resolve()
            if output.exists():
                raise CarryProofError(f"Output already exists: {output}")
            header = create_parity(source, output, chunk_size=args.chunk_size, stripe_width=args.stripe_width)
            console.success(f"Recovery data created: {output}")
            print(f"Protected: {human_size(header['file_size'])} in {len(header['chunk_hashes'])} chunks")
            print(f"SHA-256:  {header['file_sha256']}")
            return 0
        if args.command == "recover":
            source = args.file.expanduser().resolve()
            output = (args.output or source.with_name(source.name + ".recovered")).expanduser().resolve()
            if output.exists():
                raise CarryProofError(f"Output already exists: {output}")
            result = recover_with_parity(source, args.parity.expanduser().resolve(), output)
            console.success(f"Verified and recovered: {output}")
            print(f"Repaired chunks: {result['repaired_chunks']}")
            print(f"SHA-256:        {result['sha256']}")
            return 0
        if args.command == "serve":
            run_portal(args.path, args.host, args.port, args.code, args.ttl, args.open_browser, demo=args.demo)
            return 0
        if args.command == "doctor":
            console.heading(f"{APP_NAME} doctor")
            print(f"Python:         {sys.version.split()[0]}")
            print(f"Executable:     {sys.executable}")
            print("Runtime deps:   0 third-party packages")
            with tempfile.TemporaryDirectory(prefix="carryproof-doctor-") as temporary:
                root = Path(temporary)
                original = root / "sample.bin"
                original.write_bytes(bytes(range(256)) * 100)
                parity = root / "sample.cproof"
                damaged = root / "damaged.bin"
                recovered = root / "recovered.bin"
                create_parity(original, parity, chunk_size=4096, stripe_width=4)
                data = bytearray(original.read_bytes())
                data[5000:5200] = b"\x00" * 200
                damaged.write_bytes(data)
                result = recover_with_parity(damaged, parity, recovered)
                if recovered.read_bytes() != original.read_bytes() or not result["ok"]:
                    raise CarryProofError("Parity self-test failed")
            console.success("Self-test:      PASS")
            return 0
        raise CarryProofError(f"Unknown command: {args.command}")
    except CarryProofError as exc:
        print(f"carryproof: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
