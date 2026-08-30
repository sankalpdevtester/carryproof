#!/usr/bin/env python3
"""Generate a safe, synthetic CarryProof demonstration corpus."""

from __future__ import annotations

import argparse
import shutil
import struct
import zipfile
import zlib
from pathlib import Path


HERE = Path(__file__).resolve().parent


def jpeg_with_private_metadata() -> bytes:
    tiff = bytearray(b"II\x2a\x00\x08\x00\x00\x00")
    tiff += b"\x02\x00"
    tiff += b"\x10\x01\x02\x00\x06\x00\x00\x00\x26\x00\x00\x00"
    tiff += b"\x25\x88\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00"
    tiff += b"\x00\x00\x00\x00Canon\x00"
    exif = b"Exif\x00\x00" + bytes(tiff)
    comment = b"synthetic private comment"
    return (
        b"\xff\xd8\xff\xe1"
        + struct.pack(">H", len(exif) + 2)
        + exif
        + b"\xff\xfe"
        + struct.pack(">H", len(comment) + 2)
        + comment
        + b"\xff\xda\x00\x02synthetic-image-data\xff\xd9"
    )


def png_chunk(kind: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(kind)
    checksum = zlib.crc32(data, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", checksum)


def png_with_private_metadata() -> bytes:
    ihdr = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"tEXt", b"Author\x00Synthetic User")
        + png_chunk(b"IDAT", zlib.compress(b"\x00\x30\x80\xc0"))
        + png_chunk(b"IEND", b"")
    )


def macro_document(path: Path) -> None:
    content_types = b'''<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>'''
    core = b'''<?xml version="1.0"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:creator>Synthetic User</dc:creator><cp:lastModifiedBy>Demo Machine</cp:lastModifiedBy>
</cp:coreProperties>'''
    relationships = b'''<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="hyperlink" Target="https://tracker.invalid/demo" TargetMode="External"/>
</Relationships>'''
    entries = {
        "[Content_Types].xml": content_types,
        "word/document.xml": b"<document>synthetic demo document</document>",
        "docProps/core.xml": core,
        "word/_rels/document.xml.rels": relationships,
        "word/vbaProject.bin": b"synthetic macro marker",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)


def make_corpus(root: Path) -> None:
    inbox = root / "inbox"
    hostile = root / "hostile"
    inbox.mkdir(parents=True)
    hostile.mkdir()

    (inbox / "photo-with-gps.jpg").write_bytes(jpeg_with_private_metadata())
    (inbox / "image-with-author.png").write_bytes(png_with_private_metadata())
    macro_document(inbox / "project-brief.docm")
    (inbox / "notes.txt").write_text(
        "Synthetic contact: demo.person@example.invalid\nInternal address: 192.0.2.42\n",
        encoding="utf-8", newline="\n",
    )
    (inbox / "duplicate-a.txt").write_text("duplicate demonstration\n", encoding="utf-8", newline="\n")
    (inbox / "duplicate-b.txt").write_text("duplicate demonstration\n", encoding="utf-8", newline="\n")

    (hostile / "invoice.txt").write_bytes(b"MZ" + b"\x00" * 128)
    with zipfile.ZipFile(hostile / "unsafe-archive.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../outside.txt", b"synthetic traversal entry")
        archive.writestr("expands.txt", b"0" * (11 * 1024**2))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "generated")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists():
        if not args.overwrite:
            parser.error(f"output already exists: {output}; use --overwrite")
        if output == Path(output.anchor) or output == HERE or HERE not in output.parents:
            parser.error("refusing to replace an output outside the demo directory")
        shutil.rmtree(output)
    make_corpus(output)
    print(f"Demo corpus created: {output}")
    print(f"Preparation input:  {output / 'inbox'}")
    print(f"Hostile scan input: {output / 'hostile'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
