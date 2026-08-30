#!/usr/bin/env python3
"""Build the public judge demo from synthetic files and the real runtime."""

from __future__ import annotations

import hashlib
import html
import json
import shutil
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "demo" / "web"
REPOSITORY = "https://github.com/PirateKingLuffie/carryproof"
DESCRIPTION = (
    "Turn a folder into a self-contained handoff: prepared files, a before/after "
    "report, and a browser verifier. Python standard library only."
)

sys.path.insert(0, str(ROOT))
import build
import carryproof as cp
from demo.make_demo import make_corpus


def insert_before(document: str, marker: str, content: str) -> str:
    if document.count(marker) != 1:
        raise ValueError(f"Expected one template marker: {marker}")
    return document.replace(marker, content + marker, 1)


def demo_document(capsule: str) -> str:
    navigation = (WEB / "navigation.html").read_text(encoding="utf-8")
    guide = (WEB / "guide.html").read_text(encoding="utf-8")
    resources = (WEB / "resources.html").read_text(encoding="utf-8")
    css = (WEB / "guide.css").read_text(encoding="utf-8")
    script = (WEB / "guide.js").read_text(encoding="utf-8")
    metadata = (
        f'<meta name="description" content="{html.escape(DESCRIPTION, quote=True)}">'
        '<meta property="og:title" content="CarryProof | Guided demo">'
        f'<meta property="og:description" content="{html.escape(DESCRIPTION, quote=True)}">'
        '<meta property="og:type" content="website">'
        '<meta name="twitter:card" content="summary">'
    )
    document = capsule.replace(
        "<title>CarryProof offline capsule</title>",
        metadata + "<title>CarryProof | Guided demo</title>",
        1,
    )
    document = insert_before(document, "</style>", "\n" + css)
    document = insert_before(document, '<main class="shell">', navigation + '<div class="demo-layout">' + guide)
    document = document.replace('<header class="top">', '<header class="top capsule-header">', 1)
    document = document.replace('<h1>CarryProof capsule</h1>', '<h1>CarryProof</h1>', 1)
    document = document.replace('<p class="eyebrow">File handoff</p>', '<p class="eyebrow">Interactive sample handoff</p>', 1)
    document = document.replace(
        '<p id="subtitle"></p>',
        '<p>Prepared files, their change record, and the recipient\'s verifier. All in one file.</p>'
        '<p id="subtitle" class="sample-name"></p>',
        1,
    )
    document = insert_before(document, '<footer class="notice">', resources)
    document = document.replace('</main>', '</main></div>', 1)
    document = insert_before(document, '</body>', '<script>\n' + script + '\n</script>')
    document = document.replace('__REPOSITORY__', html.escape(REPOSITORY, quote=True))
    return document


def report_document(original: cp.Report, prepared: cp.Report) -> bytes:
    document = cp.generate_report_html(original, prepared, include_generated=False).decode("utf-8")
    document = document.replace(
        '<span id="status" class="status">',
        '<a class="demo-back" href="./">Guided demo</a><span id="status" class="status">',
        1,
    )
    document = insert_before(document, '</style>', (
        '\n.topbar{height:auto;min-height:72px;gap:12px;flex-wrap:wrap;padding-top:12px;padding-bottom:12px}'
        '.demo-back{font-size:13px;color:var(--teal);font-weight:700;text-decoration:none}'
    ))
    return document.encode("utf-8")


def build_site(destination: Path) -> dict[str, str]:
    destination.mkdir(parents=True, exist_ok=True)
    build.prove_stdlib(build.imported_modules(build.SOURCE))
    with tempfile.TemporaryDirectory(prefix="carryproof-site-") as temporary:
        workspace = Path(temporary)
        make_corpus(workspace / "fixtures")
        result = cp.prepare_workflow(
            workspace / "fixtures" / "inbox",
            workspace / "prepared",
            overwrite=False,
            content_scan=True,
            strip_active=True,
            parity=True,
            chunk_size=4096,
            stripe_width=4,
        )
        if not cp.verify_capsule(Path(result["capsule"]))["ok"]:
            raise ValueError("Generated demo capsule failed verification")
        if not cp.verify_bundle(Path(result["bundle"]))["ok"]:
            raise ValueError("Generated demo bundle failed verification")

        for key, filename in (
            ("capsule", "sample.carryproof.html"),
            ("bundle", "sample.carryproof.zip"),
            ("parity", "sample.carryproof.zip.cproof"),
        ):
            shutil.copyfile(result[key], destination / filename)
        capsule = Path(result["capsule"]).read_text(encoding="utf-8")
        (destination / "index.html").write_text(demo_document(capsule), encoding="utf-8", newline="\n")
        (destination / "report.html").write_bytes(report_document(result["original"], result["prepared"]))
        (destination / "report.json").write_bytes(cp.deterministic_json(
            cp.report_payload(result["original"], result["prepared"], include_generated=False)
        ))

    artifact = build.artifact_bytes()
    if artifact != build.artifact_bytes():
        raise ValueError("Runtime builds are not reproducible")
    (destination / "carryproof.pyz").write_bytes(artifact)
    (destination / "LICENSE.txt").write_text(
        (ROOT / "LICENSE").read_text(encoding="utf-8"), encoding="utf-8", newline="\n",
    )
    (destination / "vercel.json").write_text(
        (WEB / "vercel.json").read_text(encoding="utf-8"), encoding="utf-8", newline="\n",
    )
    (destination / ".vercelignore").write_text(
        (WEB / ".vercelignore").read_text(encoding="utf-8"), encoding="utf-8", newline="\n",
    )
    (destination / "404.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width,initial-scale=1"><title>CarryProof | Not found</title>'
        '<body style="font:16px system-ui;padding:40px"><h1>Page not found</h1>'
        '<a href="/">Return to CarryProof</a></body></html>',
        encoding="utf-8", newline="\n",
    )
    names = (
        "index.html", "report.html", "report.json", "sample.carryproof.html",
        "sample.carryproof.zip", "sample.carryproof.zip.cproof", "carryproof.pyz", "LICENSE.txt",
    )
    hashes = {name: hashlib.sha256((destination / name).read_bytes()).hexdigest() for name in names}
    (destination / "SHA256SUMS.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in hashes.items()), encoding="ascii", newline="\n",
    )
    return hashes


def main() -> int:
    destination = ROOT / "dist" / "demo"
    hashes = build_site(destination)
    print(f"Public demo built: {destination}")
    print("Only generated sample files and reviewed runtime artifacts are published.")
    print(json.dumps(hashes, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
