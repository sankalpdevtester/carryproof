# CarryProof

**One file carries the handoff, its change record, and its receiver.**

CarryProof prepares a folder for sharing and packages it as one self-contained HTML capsule. The capsule carries prepared file bytes, original and prepared fingerprints, recorded transformations, a canonical manifest, and a SHA-256 content seal. A recipient with a current Web Crypto-capable browser can verify and extract the prepared files without installing CarryProof. Prepared does not mean malware-free; unresolved findings remain visible in the report.

The same run also produces a deterministic ZIP and repair data. An optional authenticated LAN portal exposes these artifacts. The runtime uses only the Python standard library plus native browser APIs. There is no `pip install`, required cloud service, database server, or receiver installation.

[Live guided demo](https://carryproof-sage.vercel.app/) | [Source on GitHub](https://github.com/PirateKingLuffie/carryproof) | [Download the Python executable](https://carryproof-sage.vercel.app/carryproof.pyz)

The public judge demo has a five-step walkthrough that opens automatically. It runs the real capsule verifier against synthetic files, including a one-byte corruption check and a verified text-file download. No login, access code, or upload is needed for the hosted sample. [Hosting and reproducible demo build](HOSTING.md).

## The real-world workflow

People routinely send photographs containing GPS coordinates, documents containing author names and revision history, archives containing unsafe extraction paths, and files whose extensions do not match their contents. Existing answers are fragmented across metadata tools, archive scanners, Office inspectors, checksum utilities, parity programs, web servers, and file-transfer applications.

CarryProof makes those checks one coherent operation and sends the evidence with the result:

```text
inspect -> sanitize copies -> inspect again -> seal offline capsule -> bundle + repair -> handoff
```

The original input is never modified.

## Quick start

Requires Python 3.11 or newer.

```console
python build.py
python dist/carryproof.pyz prepare path/to/files
```

### 60-second judge path

```console
python demo/make_demo.py --overwrite
python dist/carryproof.pyz prepare demo/generated/inbox --overwrite
python dist/carryproof.pyz serve demo/generated/inbox-carryproof --host 127.0.0.1 --port 8765 --code 12345678 --demo --ttl 10m
```

Open [the local demo](http://127.0.0.1:8765). The login page displays **Judge demo code: 1234 5678**. Select **Use code**, unlock the handoff, open the offline capsule, and select **Verify all payloads**. Then select **Test one-byte change**: the same verification function rejects an altered in-memory copy without modifying any embedded file. The complete timed presentation is in [DEMO.md](DEMO.md).

The default output is a sibling directory named `<input>-carryproof` containing:

```text
input-carryproof/
|-- cleaned/                         sanitized and unchanged prepared copies
|-- input.carryproof.html            self-verifying offline handoff capsule
|-- input.carryproof.zip             deterministic, self-describing bundle
|-- input.carryproof.zip.cproof      repair data for the bundle
|-- carryproof-capsule.json          canonical capsule metadata and content seal
|-- carryproof-report.html           interactive before/after report
`-- carryproof-report.json           machine-readable report
```

The capsule contains prepared copies, no external scripts, fonts, or analytics, and makes no network requests. Every download checks the manifest and the requested payload. The embedded verifier cannot authenticate itself: for a sensitive handoff, obtain the complete HTML file's SHA-256 through a trusted separate channel and check it before opening the HTML.

## The proof-carrying capsule

The capsule is the primary CarryProof artifact:

1. The Python runtime streams prepared files into a deterministic HTML document as Base64 payloads.
2. A canonical JSON manifest records each prepared path, size, type, and SHA-256, plus original-to-prepared transformations.
3. SHA-256 over the exact canonical manifest becomes its content seal; a separate hash covers the complete HTML file.
4. The recipient browser hashes that manifest and every decoded payload again using Web Crypto.
5. A file is released for download only after its size and SHA-256 match.

The capsule includes bytes from the prepared directory, not a second copy of the originals. Unsupported files and failed sanitizations can remain byte-identical to their originals, including unresolved risks. The ledger records the sender's claimed actions; it is not an independent proof that all sensitive content was removed.

`verify` can inspect the capsule without executing its JavaScript:

```console
python carryproof.py verify input.carryproof.html
python carryproof.py verify input.carryproof.html --sha256 TRUSTED_64_HEX_DIGIT_HASH
```

Without the independently supplied hash, verification checks internal consistency only. The manifest seal does not cover the verifier code, CSS, or surrounding HTML. Neither hash is a digital signature or proof of sender identity. `prepare` prints both hashes and writes them to `carryproof-capsule.json`; copying that sidecar alongside the capsule is not an independent trust channel.

Web Crypto requires a secure browser context. Localhost works; local HTML files are supported by current browsers subject to browser policy. A capsule served over ordinary non-localhost HTTP may not be able to verify in place. Use the downloaded file or CLI in that case.

## What it detects

- File types identified from content rather than filename alone.
- Executables disguised with harmless extensions.
- ZIP and TAR path traversal, absolute paths, unsafe links, special files, excessive member counts, and suspicious expansion ratios.
- Nested ZIP-family archives within bounded depth and size limits.
- Office macros, ActiveX/OLE embeddings, external relationships, and authorship/history properties.
- JPEG EXIF, GPS, XMP, IPTC, camera identifiers, and comments.
- PNG text, XMP, EXIF, and timestamp chunks with CRC validation.
- SVG scripts, event handlers, external references, and metadata blocks.
- PDF metadata and active-content markers.
- Common visible secrets and identifiers in text, JSON, JSONL, CSV, XML, and configuration files.
- Malformed JSON/JSONL and inconsistent or malformed CSV.
- Byte-identical duplicate files and potentially reclaimable space.

Secret values found during visible-content inspection are never copied into the report. CarryProof reports only the type and number of matches.

## What it sanitizes

| Format | Safe-copy behavior |
| --- | --- |
| JPEG | Removes EXIF, XMP, IPTC/Photoshop metadata, and comments without recompressing image data. |
| PNG | Removes text/XMP, EXIF, and timestamp chunks while preserving image chunks byte-for-byte. |
| DOCX/XLSX/PPTX | Clears private properties and rewrites a deterministic OOXML container. |
| DOCM/XLSM/PPTM | Removes VBA/active parts and external relationships, converts the main type to its macro-free equivalent, and uses a `.sanitized.docx/.xlsx/.pptx` output name. |
| SVG | Removes metadata; the default `prepare` workflow also removes scripts, event handlers, and external executable references. |
| PDF | Scan only. PDFs are copied unchanged because a partial PDF rewriter would create false confidence. |
| Other files | Copied unchanged, then included in the second inspection. |

`prepare` strips supported active Office and SVG content by default. Use `--keep-active` only when the active behavior is intentional and will be reviewed.

## Commands

```console
# Read-only inspection with JSON and standalone HTML reports
python carryproof.py scan PATH --content

# Create sanitized copies and compare before/after findings
python carryproof.py clean PATH --strip-active

# Complete workflow, including the offline capsule
python carryproof.py prepare PATH

# Verify the capsule without running its embedded code
python carryproof.py verify files.carryproof.html

# Verify every bundled file against its SHA-256 manifest
python carryproof.py verify files.carryproof.zip

# Create repair data for any file
python carryproof.py protect large-file.bin --chunk-size 1MiB --stripe-width 8

# Repair one damaged or missing chunk in each stripe
python carryproof.py recover damaged.bin large-file.bin.cproof

# Share a prepared output over the local network
python carryproof.py serve PATH --ttl 30m --open

# Judge/demo mode deliberately shows its code on the login screen
python carryproof.py serve PATH --code 12345678 --demo --ttl 30m

# Verify the runtime and parity implementation
python carryproof.py doctor
```

Commands return `0` on success, `2` for usage/runtime errors, `3` when an inspection completes with high or critical findings, and `4` when artifact verification fails. A nonzero inspection result does not mean the scan crashed; it means automation should stop and request review. This is a review signal, not enforced quarantine: prepared output can still contain files with findings.

## Repair data

The `.cproof` format divides a file into fixed-size chunks and groups them into stripes. It stores a SHA-256 hash for every data chunk plus one XOR parity chunk per stripe. CarryProof can detect every changed chunk and reconstruct exactly one missing or corrupted chunk in each stripe. It verifies the final file hash before publishing the recovered output.

This is intentionally not described as Reed-Solomon: two damaged chunks in one stripe cannot be recovered. The limitation is detected and fails without publishing a partial result. See [FORMAT.md](FORMAT.md).

## Private browser sharing

`serve` starts a read-only HTTP portal using `ThreadingHTTPServer`. It generates an eight-digit access code, rate-limits failed logins, issues an `HttpOnly` `SameSite=Strict` session cookie, constrains every resolved path to the shared root, supports resumable byte-range downloads, and serves a restrictive Content Security Policy. Prepared outputs open to an evidence dashboard with direct capsule, before/after report, bundle, and recovery access.

`--demo` deliberately prints the access code on the login page so a judge can enter without terminal access. It is opt-in and must not be used for sensitive real-world sharing.

The portal uses ordinary HTTP because Python's standard library cannot generate a trusted certificate. Treat it as a convenience for a trusted local network, not an internet-facing file server. Sensitive transfers on an untrusted network require a trusted TLS terminator, which would be an external runtime dependency and is deliberately outside this submission.

## Zero-dependency proof

The one-command build performs all of the following:

1. Parses runtime imports with `ast`.
2. Checks every import against `sys.stdlib_module_names`.
3. Verifies that `requirements.txt` is empty.
4. Runs the complete `unittest` suite.
5. Builds the executable `.pyz` twice.
6. Fails unless both artifacts are byte-identical.
7. Writes both SHA-256 hashes to `deps-proof.txt`.

```console
python build.py
```

No source has been vendored. CarryProof was built for the August 28-31, 2026 Zero Dependency hackathon. The complete substitution ledger is in [STDLIB.md](STDLIB.md).

## Track and bonus challenges

Primary track: **E - Security & Crypto Utilities**. CarryProof is a privacy and file-safety utility. It composes standard-library hashing and authentication primitives but does not invent encryption.

- **Single File (+5):** all runtime implementation, capsule generator and browser verifier, HTTP UI, report UI, scanners, sanitizers, bundle logic, and repair logic live in `carryproof.py`.
- **Reproducible Build (+5):** two builds are compared byte-for-byte and both hashes are published.
- **STDLIB Log (+3):** more than ten nontrivial package substitutions are documented.

CarryProof does not claim the Package Killer bonus: it is a complete product and file format, not a clean reimplementation of one named package.

## Honest limits

- CarryProof is not antivirus software and does not identify all malware.
- Content detection is pattern-based and can produce false positives and false negatives.
- PDF support is intentionally scan-only.
- Rewriting complex Office or SVG files can alter active behavior; always open and review prepared copies.
- OOXML comments and tracked changes are reported but not silently erased because they may be visible document content.
- RAR and 7z are identified but not unpacked because Python's standard library has no decoder for them.
- The portal is intended for a trusted LAN and is not a production web server.
- Capsules add roughly 33% Base64 overhead. Browsers retain the HTML and parsed payload data, plus temporary decoded bytes during checks and downloads. Large handoffs are better served as ZIPs.
- The independent capsule verifier accepts HTML files up to 128 MiB. ZIP verification limits expanded content to 2 GiB and the manifest to 32 MiB.
- A manifest seal excludes the browser verifier code. Only a separately trusted whole-file hash checks that code as well; neither authenticates the sender by itself.
- Prepared copies may retain secrets, active content, or malware. Scores are heuristic weights, not probabilities or safety certificates.
- Demo mode intentionally reveals its access code and is unsuitable for sensitive files.
- XOR parity repairs one bad chunk per stripe, not arbitrary multi-chunk loss.
- Files can change while a directory scan is running. CarryProof hashes what it reads but does not freeze the filesystem.

Read [SECURITY.md](SECURITY.md) before relying on CarryProof for sensitive material.

## Development

```console
python -m unittest discover -s tests -v
python build.py
python dist/carryproof.pyz doctor
```

Test fixtures are generated from standard-library code; the repository contains no copied test corpus or third-party assets.

## License

MIT. See [LICENSE](LICENSE).
