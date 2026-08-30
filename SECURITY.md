# Security model

CarryProof reduces accidental disclosure and unsafe file handling. It is not a malware verdict, anonymity guarantee, or replacement for expert review.

## Assets

- Original user files, which must never be modified.
- Sanitized copies, capsule payloads, and bundle contents.
- Hidden metadata, visible secrets, and file structure findings.
- Bundle integrity manifests and repair data.
- Files exposed temporarily through the local portal.

## Trust boundaries

1. **Input to scanner:** every filename, archive member, XML document, and binary structure is untrusted.
2. **Original to sanitized output:** transformations must write to separate paths and publish atomically.
3. **Capsule or bundle to recipient:** SHA-256 detects changes but does not prove who created the artifact.
4. **Portal to local network:** clients are untrusted even when the network is familiar.
5. **Report to browser:** filenames and findings are untrusted presentation data.

## Defensive choices

- Inputs are opened read-only during inspection.
- Outputs cannot be the source, its parent, its child, or a drive root.
- Sanitizers write temporary sibling files, flush them, call `fsync`, and publish with `os.replace`.
- ZIP and TAR names are checked for parent traversal, roots, drive prefixes, NUL bytes, links, and special entries.
- Archives are inspected without extraction.
- Member count, nested depth, nested size, expanded size, and compression-ratio limits bound archive work.
- XML is parsed only after part/file size limits and no network resolution is performed.
- Reports omit values matched by the visible-secret scanner.
- Report JSON escapes `<` before embedding into HTML, and dynamic UI values are HTML-escaped.
- Capsule manifests use deterministic JSON, escape script boundaries, and include only prepared file bytes.
- Every capsule download checks the manifest seal and the payload's exact size and SHA-256 before creating a download.
- The capsule CSP restricts resource loading and connections. It is not a sandbox for arbitrary modified HTML, browser extensions, or navigation.
- Independent capsule verification uses `HTMLParser` and never executes embedded JavaScript.
- Bundle verification requires a valid manifest, matching inventory, unique paths, sizes, ZIP CRCs, and SHA-256 hashes. Metadata-name collisions fail at creation.
- Parity repair validates per-chunk hashes and the final whole-file SHA-256 before publishing output.
- The portal resolves symlinks and requires the final path to remain under the shared root.
- Portal sessions use 256-bit random tokens in `HttpOnly`, `SameSite=Strict` cookies.
- Access codes are rate-limited to six failed attempts per source address per minute.
- The portal is read-only and does not accept uploads, deletes, renames, or remote commands.
- Range requests are single-range, bounds-checked, and streamed.
- Browser responses set CSP, no-sniff, frame denial, no-referrer, and same-origin resource policy headers.

## Sanitization boundary

### JPEG and PNG

Metadata containers are removed while encoded image data remains unchanged. CarryProof does not decode or re-encode pixels. A malformed structure causes a finding or a failed sanitizer, not a best-effort rewrite presented as success.

### OOXML

Private properties are cleared. With active stripping enabled, known VBA, ActiveX, OLE, custom UI, external link parts, and relationships are removed. Macro-enabled main content types are converted to their corresponding macro-free OOXML type and output names use macro-free extensions.

Office files are extensible ZIP containers. CarryProof cannot prove the absence of every vendor-specific active feature. Open and review sanitized copies before release.

### SVG

Metadata is removed. Active stripping removes script elements, event-handler attributes, and external/executable references recognized by the implementation. XML is reserialized, so formatting and namespace prefixes may change.

### PDF

PDFs are scan-only and copied unchanged. Safe rewriting requires a complete parser, object graph, stream/filter handling, incremental-update handling, and signature awareness that the standard library does not provide. CarryProof refuses to hide that boundary.

### Other formats

Unknown and unsupported files are copied unchanged and inspected again. A sanitizer failure also falls back to an unchanged copy with a recorded failure. A copied file is not the same as a sanitized file; the report states which action occurred. These copies are included in the capsule and ZIP, even when findings remain. Exit code `3` asks automation to stop for review; CarryProof does not enforce quarantine.

## Portal boundary

The built-in server uses plain HTTP. The access code prevents casual browsing but does not encrypt network traffic. Anyone able to observe a hostile network may read transferred data or session traffic.

Use the portal only on a trusted local network. Do not expose it through router port forwarding, a public IP, or an untrusted Wi-Fi network. For encrypted internet use, place a separately managed trusted TLS reverse proxy in front of CarryProof; that proxy is intentionally outside this zero-dependency artifact.

Python documents `http.server` as unsuitable for production. CarryProof's server is an ephemeral read-only transfer convenience, not a daemon.

`--demo` intentionally discloses the access code in the login document. It exists only so judges without terminal access can enter a demonstration. Never enable it while sharing sensitive real-world files. Without this flag, the code is printed only to the local terminal and is not serialized into the portal HTML or unauthenticated API responses.

## Capsule boundary

An offline capsule is a self-contained HTML application, not encryption. Anyone who receives it can inspect and extract every prepared payload. Base64 is transport encoding and provides no confidentiality.

The browser rechecks integrity but still participates in the trust boundary. A hostile extension, compromised browser, or local process may read extracted data. The unmodified capsule makes no network requests and its CSP restricts resource loading. That policy cannot control extensions or the operating system, is not a general navigation sandbox, and can be removed by someone editing the HTML.

The content seal is SHA-256 over the exact canonical manifest bytes. It does **not** cover the HTML, CSS, or JavaScript verifier. An attacker could change the embedded verifier to display success without changing this seal. Do not open an untrusted HTML application merely because its displayed seal matches.

For sensitive handoffs, obtain the **whole-capsule SHA-256** through a trusted separate channel and run `carryproof verify capsule.html --sha256 EXPECTED_HASH` using a trusted installation before opening the HTML. This hashes the complete artifact, then parses and verifies its data without executing any scripts. The test suite explicitly changes verifier code: internal payload checks still pass, while the separately supplied whole-file hash fails.

Without a trusted external hash, both CLI and browser verification establish internal consistency only. If an attacker controls the artifact and the trusted channel, matching hashes offer no authenticity. The transformation ledger is a sender-generated record, not proof that a sanitizer removed all sensitive content.

## Integrity and authenticity

SHA-256 manifests detect changes relative to those manifests. They do not authenticate the creator, and self-consistent replacement is possible. A separately trusted complete artifact hash can detect replacement, including modified verifier code and ZIP reports. Capsule payload checks and ZIP payload manifests alone do not cover all presentation code or report bytes.

The `.cproof` sidecar is recovery data, not a signature or encryption format. XOR parity repairs one bad chunk per stripe. It detects but cannot repair two or more damaged chunks in the same stripe.

## Known residual risks

- Files may change between enumeration, inspection, cleaning, and bundling.
- Pattern-based secret detection has false positives and false negatives.
- Binary marker detection in PDFs can miss obfuscated actions or flag benign compressed data.
- Compression bombs below configured thresholds can still consume meaningful CPU and disk space in another extractor.
- Large directory trees can consume significant scan time and report memory.
- Capsules add Base64 size overhead. A browser holds the HTML and parsed payloads, plus decoded bytes and download blobs; verification is not constant-total-memory.
- CLI capsule verification reads up to 128 MiB of HTML into memory. Bundle verification limits expanded data to 2 GiB, inventory to 100,000 files, and its manifest to 32 MiB.
- Browser SHA-256 requires Web Crypto in a secure context; ordinary LAN HTTP is not sufficient in many browsers.
- External applications used to open sanitized outputs may have their own vulnerabilities.
- A local process with the same user privileges can read files, memory, access codes, or portal traffic.
- File permissions, alternate data streams, extended attributes, and platform-specific metadata are not preserved or sanitized consistently across operating systems.

## Reporting a vulnerability

Do not attach a sensitive real-world document to a public issue. Provide a minimal generated fixture, exact command, Python version, operating system, observed behavior, and expected behavior. Until a public repository contact is added, use the private contact method listed in the hackathon submission.
