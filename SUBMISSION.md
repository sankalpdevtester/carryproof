# Zero Dependency submission: CarryProof

## Submission fields

- **Project:** CarryProof
- **Primary track:** E - Security & Crypto Utilities
- **One-line pitch:** One offline file carries prepared documents, their change record, and the recipient's integrity verifier, with zero third-party runtime packages.
- **Repository:** https://github.com/PirateKingLuffie/carryproof
- **Live demo:** https://carryproof-sage.vercel.app/ (automatic five-step walkthrough; no login)
- **Demo video:** `[FIVE_MINUTE_VIDEO_URL]`
- **Team:** `[NAME OR TEAM, 1-4 PEOPLE]`
- **Contact:** `[REACHABLE_EMAIL]`
- **License:** MIT
- **Build command:** `python build.py`
- **Run command:** `python dist/carryproof.pyz --help`

## What it does

CarryProof builds a **proof-carrying handoff**: a self-contained artifact combining prepared bytes with sender-recorded evidence and an integrity verifier. This is the project's design, not a claim to have invented self-extracting archives or to be the first comparable tool.

1. Detects hidden privacy metadata, visible secrets, disguised file types, unsafe archives, Office macros/embeddings/external links, active SVG/PDF markers, malformed structured data, and duplicates.
2. Creates separate sanitized JPEG, PNG, OOXML, and SVG copies while preserving originals.
3. Reopens and reinspects prepared copies so the report shows what actually changed.
4. Packages prepared bytes, original fingerprints, recorded transformations, and a canonical manifest into one deterministic offline HTML capsule.
5. Lets the recipient verify the manifest and every payload with browser-native SHA-256 before extracting files, with no install or server.
6. Also builds a byte-reproducible ZIP, adds corruption-repair data, and optionally serves an authenticated read-only LAN dashboard.
7. Independently verifies capsules without executing their scripts, with optional trusted whole-file SHA-256 checks covering the verifier code too.

## Why it matters

The moment before sharing is fragmented. A sender may run a metadata tool, a macro inspector, a checksum utility, and a transfer app, but the recipient still gets bytes without the record of what happened. CarryProof sends prepared bytes and that record together. The recipient needs a current browser with Web Crypto in an allowed context, not an installed receiver application. Unresolved findings and unchanged files remain explicit.

## Zero-dependency proof

`python build.py`:

- confirms `requirements.txt` is empty;
- parses every import in the runtime source;
- checks each import against `sys.stdlib_module_names`;
- runs the standard-library test suite;
- builds the artifact twice;
- verifies byte-identical output;
- writes both SHA-256 hashes to `deps-proof.txt`.

The runtime implementation is one source file. No source or test corpus is vendored.

## Scoring case

### Functionality and usefulness (35%)

One command produces a self-verifying recipient artifact, sanitized copies, before/after evidence, a deterministic integrity bundle, repair data, and an optional phone-accessible portal. The capsule can be emailed or copied to USB and opened directly in a browser.

### Zero-dependency craft (30%)

`STDLIB.md` documents more than twenty genuine substitutions spanning binary parsing, OOXML, archive safety, secret scanning, streamed Base64 capsule generation, canonical serialization, browser verification, deterministic builds, HTTP sessions, range serving, testing, atomic writes, and recovery coding.

### Code quality and idiom (25%)

The implementation uses dataclasses, context managers, streaming hashes and Base64, explicit limits, stable finding codes, atomic publication, constant-time comparisons, path confinement, structured JSON, standard exception boundaries, and focused tests. Coverage includes manifest and payload tampering, altered verifier code, changed inventory, filename collisions, concurrent-file change rejection, reproducibility, and the public demo export.

### Innovation (10%)

The distinctive demonstration is a handoff that is also its own receiver application. Generated HTML carries prepared bytes, original fingerprints, recorded transformations, and native browser verification. A live one-byte mutation is rejected by the same comparison used for downloads, without modifying the embedded files. A separate CLI check can verify the data without executing the embedded application. None of this turns a checksum into proof of malware safety or sender identity.

## Bonus challenges

- **Single File (+5):** `carryproof.py` contains the complete runtime, capsule generator/verifier, and all three browser interfaces.
- **Reproducible Build (+5):** two byte-identical build hashes are published in `deps-proof.txt`.
- **STDLIB Log (+3):** more than ten nontrivial substitutions are documented.

Package Killer is not claimed. CarryProof is a product and file format rather than a reimplementation of one named package.

## Honest limitations

CarryProof is not antivirus or an enforced quarantine. PDF rewriting is scan-only; unchanged risky inputs may still enter the prepared artifact. The manifest seal excludes verifier code, so sensitive use requires a trusted whole-file hash before opening the HTML. Capsules are encoded, not encrypted. Browser policies can restrict Web Crypto, the HTTP portal is trusted-LAN-only, pattern detection is imperfect, and XOR parity repairs one bad chunk per stripe. These boundaries are tested or documented in `README.md`, `SECURITY.md`, and `FORMAT.md`.

## Final checklist

Verification on August 30, 2026 used Windows and Python 3.12.10:

- `python build.py`: 46 passing tests, 36 standard-library imports, zero third-party runtime imports, two identical artifact hashes.
- `python -S -m unittest discover -s tests -q`: all 46 tests pass with site-packages disabled.
- Isolated `python -I -S` artifact runs: preparation, capsule/ZIP verification, corruption rejection, one-chunk recovery, and the doctor self-test pass.
- Browser checks on localhost: public demo-code entry, individual download, all-payload verification, one-byte rejection, fingerprints, and original/prepared report switching pass.
- Public HTTPS demo: anonymous access and byte-for-byte checks pass for the guided page, report, capsule, ZIP, recovery data, Python executable, and checksums. Environment files, hosting metadata, and Git configuration return 404.
- Guided tour: first-load help, replay/close, five step controls, real verification, one-byte rejection, and report navigation pass on desktop and narrow mobile layouts.
- Hosted walkthrough: verification, one-byte rejection, and verified text-file download also pass on the public HTTPS deployment.
- Fresh unauthenticated GitHub clone: all 46 tests pass with site-packages disabled; the demo builder produces the same eight published artifact hashes.
- Layout checks: 1440x900 desktop, 390x844 phone, and 320x740 narrow phone; no detected page or capsule-control overflow after fixes. No browser console warnings/errors during the checked capsule flow.
- Direct downloaded-file launch was not browser-tested because the embedded browser did not permit local-file navigation. Localhost testing is not evidence of offline launch; complete the manual check below before recording that claim.

These checks use synthetic fixtures and do not establish comprehensive format compatibility or malware safety.

- [x] Working program
- [x] One-command build
- [x] Empty dependency manifest
- [x] Generated dependency proof
- [x] README with run instructions and limits
- [x] STDLIB substitution ledger
- [x] OSI-approved license
- [x] Tests and generated adversarial fixtures
- [x] Five-minute demo script
- [x] Write-up side-quest draft
- [ ] Open the downloaded capsule offline in the intended judge browser and verify/extract a payload
- [x] Public hosted demo with an automatic judge walkthrough
- [ ] Replace video, team, and contact placeholders above
- [x] Push a public GitHub repository
- [ ] Record and publish the five-minute demo
- [ ] Submit before August 31, 2026 at 18:00 UTC
