#!/usr/bin/env python3
"""Create a deliberately corrupted copy for the CarryProof recovery demo."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--offset", type=int)
    parser.add_argument("--bytes", type=int, default=256)
    args = parser.parse_args()
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not source.is_file():
        parser.error(f"source is not a file: {source}")
    if output.exists():
        parser.error(f"output already exists: {output}")
    if output == source:
        parser.error("output must differ from source")
    shutil.copyfile(source, output)
    size = output.stat().st_size
    offset = args.offset if args.offset is not None else max(0, size // 3)
    if offset < 0 or offset >= size:
        parser.error("offset is outside the file")
    length = min(max(1, args.bytes), size - offset)
    with output.open("r+b") as handle:
        handle.seek(offset)
        original = handle.read(length)
        handle.seek(offset)
        handle.write(bytes(value ^ 0xA5 for value in original))
    print(f"Damaged {length} bytes at offset {offset}: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
