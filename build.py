#!/usr/bin/env python3
"""Build the CarryProof archive and write its dependency report."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import os
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "carryproof.py"
DIST = ROOT / "dist"
ARTIFACT = DIST / "carryproof.pyz"
PROOF = ROOT / "deps-proof.txt"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".", 1)[0])
    names.discard("__future__")
    return sorted(names)


def prove_stdlib(imports: list[str]) -> None:
    stdlib = set(sys.stdlib_module_names)
    unexpected = sorted(name for name in imports if name not in stdlib)
    if unexpected:
        raise SystemExit(f"Third-party or unknown runtime imports found: {', '.join(unexpected)}")
    requirements = ROOT / "requirements.txt"
    if requirements.exists() and requirements.read_text(encoding="utf-8").strip():
        raise SystemExit("requirements.txt is not empty")


def artifact_bytes() -> bytes:
    output = io.BytesIO()
    output.write(b"#!/usr/bin/env python3\n")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        info = zipfile.ZipInfo("__main__.py", FIXED_TIME)
        info.create_system = 3
        info.external_attr = (0o755 & 0xFFFF) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(
            info,
            SOURCE.read_text(encoding="utf-8").encode("utf-8"),
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )
    return output.getvalue()


def run_tests() -> None:
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    imports = imported_modules(SOURCE)
    prove_stdlib(imports)
    if not args.skip_tests:
        run_tests()

    first = artifact_bytes()
    second = artifact_bytes()
    if first != second:
        raise SystemExit("Reproducible build check failed: two builds differ")
    digest_one = hashlib.sha256(first).hexdigest()
    digest_two = hashlib.sha256(second).hexdigest()

    DIST.mkdir(exist_ok=True)
    ARTIFACT.write_bytes(first)
    if os.name != "nt":
        ARTIFACT.chmod(0o755)

    proof = "\n".join(
        [
            "CarryProof zero-dependency proof",
            "=================================",
            f"Python: {sys.version.split()[0]}",
            "Manifest: requirements.txt is empty",
            f"Runtime imports ({len(imports)}): {', '.join(imports)}",
            "Import classification: every runtime import is in sys.stdlib_module_names",
            "Third-party runtime imports: 0",
            "",
            "Reproducible build",
            f"Build 1 SHA-256: {digest_one}",
            f"Build 2 SHA-256: {digest_two}",
            f"Byte-identical: {'yes' if digest_one == digest_two else 'no'}",
            f"Artifact: dist/{ARTIFACT.name}",
            "",
        ]
    )
    PROOF.write_text(proof, encoding="utf-8", newline="\n")
    print(proof, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
