# Standard-library substitution log

CarryProof has zero third-party runtime dependencies and no vendored source. `requirements.txt` is intentionally empty. This document records what would normally be installed and what CarryProof uses instead.

| Typical dependency | Standard-library replacement | Why it is nontrivial here |
| --- | --- | --- |
| Click / Typer | `argparse` | Eight subcommands, typed size/duration parsing, stable exit codes, and useful command help are implemented without a CLI framework. |
| Rich / Colorama | `sys.stdout.isatty`, `os.environ`, and ANSI control sequences | Color is restricted to terminal output, disabled for redirected output, and honors `NO_COLOR`. |
| python-magic / filetype | Byte signatures, `pathlib`, and `mimetypes` | CarryProof distinguishes content from extension and treats executable mismatches as critical findings. `mimetypes` is presentation only, never the security decision. |
| Pillow / piexif / exifread | `struct` plus a bounds-checked JPEG/TIFF parser | JPEG segments and TIFF IFD pointers are decoded sufficiently to identify GPS, ownership, device, and editing metadata without decoding pixels. |
| Pillow / pypng | `struct` and `zlib.crc32` | PNG chunks are length-checked and CRC-verified; privacy chunks are removed without touching image data. |
| python-docx / openpyxl / python-pptx | `zipfile` and `xml.etree.ElementTree` | OOXML packages are classified, private properties are cleared, relationships are inspected, and deterministic sanitized containers are rebuilt. |
| oletools | `zipfile` member inspection and OOXML relationship/content-type parsing | VBA projects, ActiveX, OLE embeddings, external links, and macro-enabled document declarations are detected and optionally removed. |
| pikepdf / PyPDF2 | Bounded binary marker inspection | PDF metadata and active-content markers are reported without pretending that a partial standard-library rewriter is safe. PDFs remain scan-only. |
| lxml / defusedxml | `xml.etree.ElementTree` plus strict file/member size limits | XML work is bounded before parsing and does not resolve network resources. CarryProof limits its transformations to known OOXML/SVG structures. |
| py7zr / rarfile | Magic-byte identification with explicit unsupported findings | The standard library cannot decode these formats. CarryProof identifies them and refuses to imply that their contents were inspected. |
| zipfile-deflate64 / archive libraries | `zipfile`, `tarfile`, `gzip`, `bz2`, and `lzma` | Traversal, links, special entries, member counts, nested ZIPs, and expansion ratios are evaluated before extraction. No archive is extracted during a scan. |
| detect-secrets / trufflehog | `re` with value-suppressing reports | High-signal private-key, provider-token, JWT, email, and IP patterns are counted without copying matched secrets into output reports. |
| jsonschema / csvkit | `json` and strict `csv` readers | JSON/JSONL errors retain line and column positions; CSV structural inconsistency is reported without loading large inputs by default. |
| hashlib helper packages | `hashlib.sha256` and `hmac.compare_digest` | Every file and bundle entry receives a streaming hash, and comparisons avoid naive string equality. |
| self-extracting archive / envelope packages | `base64`, canonical `json`, streamed writes, HTML, and browser Web Crypto | CarryProof emits a deterministic document containing prepared bytes and a sender-recorded transformation ledger. Each browser download first checks the manifest and payload. This is neither encryption nor a digital signature. |
| Beautiful Soup / browser automation for HTML verification | `html.parser.HTMLParser`, `json`, `base64`, and `hashlib` | The CLI verifies capsule data without executing scripts, rejects duplicate data islands and altered payloads, and optionally checks a trusted hash of the complete HTML including its verifier code. |
| reedsolo / par2 bindings | `bytearray`, `struct`, and SHA-256 | CarryProof defines a documented XOR stripe format, detects damaged chunks, repairs one per stripe, and verifies the complete reconstructed file before atomic publication. It does not overclaim Reed-Solomon capability. |
| Flask / FastAPI / aiohttp | `http.server.ThreadingHTTPServer` | The read-only portal implements explicit routing, authentication, JSON responses, path confinement, range downloads, and security headers. |
| Werkzeug / Starlette routing | `urllib.parse` and direct route matching | A deliberately small route table reduces hidden behavior and rejects unsupported paths and methods. |
| itsdangerous / session middleware | `secrets`, `hmac`, `http.cookies`, locks, and timestamp expiry checks | Sessions are high-entropy, `HttpOnly`, `SameSite=Strict`, expiring, and protected by login rate limits. Nothing persists to disk. |
| sendfile / range-request helpers | `pathlib`, bounded file reads, and a hand-written RFC-style single-range parser | Downloads resume through byte ranges without buffering complete files in memory. |
| Jinja2 | Static HTML templates plus JSON data islands | The report, portal, and offline capsule interfaces are embedded in the one runtime source file; untrusted JSON escapes `<` before entering script elements. |
| pytest | `unittest`, `tempfile`, `unittest.mock`, and `urllib.request` | Tests cover generated format fixtures, altered manifests/payloads/verifier code, ZIP inventory, rename collisions, reproducibility, HTTP, recovery, and the public demo export without plugins or downloaded corpora. |
| PyInstaller / Shiv / PEX | `zipfile.ZipFile` and Python zipapp behavior | `build.py` creates a runnable `.pyz` with fixed metadata and verifies two byte-identical builds. |
| pip-audit / dependency scanners | `ast` and `sys.stdlib_module_names` | The build parses every runtime import, fails on an unknown top-level module, confirms the empty manifest, and writes a human-readable proof. |
| atomicwrites | `tempfile.mkstemp`, `os.fsync`, and `os.replace` | Sanitized files, capsules, reports, bundles, parity, and recovered files are published only after complete writes and flushes. |
| humanfriendly | Small strict size and duration parsers | CLI values such as `1MiB`, `2.5GB`, and `30m` are accepted without expanding the runtime surface. |
| browser/open helpers | `webbrowser` | The local portal can be opened without platform-specific shell commands or a separately installed launcher. |

## Deliberate non-replacements

Some dependency gaps are safety boundaries, not unfinished substitutions:

- No PDF writer is implemented. Partial PDF sanitization is more dangerous than an honest scan-only result.
- No RAR or 7z decoder is implemented because those algorithms are absent from the standard library.
- No TLS certificate is generated. The portal is documented as trusted-LAN-only instead of shipping custom certificate or cryptographic code.
- No custom cipher is used. Hashing, constant-time comparison, randomness, and HTTP sessions compose existing standard-library primitives only.
- No filesystem snapshot API is assumed. Concurrent external modification remains a documented consistency limit.

## Dependency proof command

```console
python build.py
```

The generated `deps-proof.txt` contains the complete runtime import list, empty-manifest check, artifact hash, second-build hash, and byte-identity result.

## Public demonstration

`demo/build_site.py` uses the same Python standard-library runtime to prepare fresh
synthetic fixtures and export the hosted sample. Its guided walkthrough is plain
HTML, CSS, and JavaScript, with native DOM events and `MutationObserver`. It calls
the capsule's existing verification functions. No tour library, UI framework,
remote assets, analytics, backend service, or external API is used by the page.
The optional static hosting provider and publishing CLI distribute the built
files; they are not dependencies of the application or its build.
