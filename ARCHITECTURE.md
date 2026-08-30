# Architecture

CarryProof is deliberately one runtime source file for the hackathon's Single File bonus. The implementation remains separated into explicit logical layers.

## Data flow

```text
filesystem input
      |
      v
content detection + streaming SHA-256
      |
      +--> format inspectors --> original report
      |
      v
safe-copy sanitizers (atomic output)
      |
      v
second inspection --> before/after report
      |
      v
proof-carrying HTML capsule
      |
      +--> recipient-side manifest + payload verification
      |
      v
deterministic ZIP + manifest
      |
      +--> XOR stripe recovery sidecar
      `--> authenticated read-only evidence portal
```

## Runtime layers

### Domain records

`Finding`, `FileRecord`, `Report`, and `ScanLimits` hold normalized state. Reports use stable finding codes so callers do not need to parse prose.

### Detection and inspection

`detect_type` makes security decisions from file bytes. Specialized inspectors handle JPEG/TIFF, PNG, ZIP/OOXML, TAR/compressed streams, PDF markers, SVG/XML, visible text, JSON/JSONL, and CSV.

Archive inspection never extracts. Nested inspection uses bounded in-memory reads only for members below the configured size and depth limits.

### Sanitization

Every sanitizer writes a separate temporary sibling, flushes and synchronizes it, then publishes atomically. The original file descriptor is read-only. Unsupported formats are copied unchanged and identified as such in the report.

### Deterministic packaging

The bundle writer normalizes order, path syntax, timestamps, permissions, compression, and JSON encoding. Both embedded report formats omit volatile timestamps. `verify_bundle` requires a valid manifest, exact payload inventory, and unique paths, then checks CRCs, sizes, and streamed SHA-256 hashes. Reserved metadata filenames are rejected at creation.

### Proof-carrying capsule

`create_capsule` builds a canonical manifest from the two inspections and a per-file transformation ledger. Prepared payloads are streamed through Base64 into a deterministic standalone HTML document. SHA-256 over the exact manifest bytes becomes the capsule seal.

The unmodified browser application makes no network requests. Before each download it hashes the manifest with Web Crypto, decodes the payload, checks its size and SHA-256, and only then releases a download. The one-byte test uses that same payload comparison on a temporary altered copy. Original hashes travel in the sender-recorded ledger; payloads come from the prepared directory, which can include unchanged originals and remaining findings.

`verify_capsule` uses `HTMLParser` to read only the two data islands and manifest seal without executing embedded scripts. It checks canonical serialization, inventory, sizes, and payload hashes. Optional `--sha256` verification covers all HTML bytes, including verifier code outside the manifest seal. This only establishes external trust when the expected hash arrives through an independent trusted channel.

### Recovery

The parity encoder uses bounded memory: one stripe parity buffer plus one input chunk. Recovery processes one stripe at a time, verifies every chunk, and atomically publishes only a whole-file hash match.

### Portal

`ThreadingHTTPServer` assigns one thread per active connection. Shared session and login-rate state is protected by an `RLock`. File data is streamed in 1 MiB blocks. The server has no write routes. An explicit demo flag injects the access code into the login page; ordinary mode never serializes it to a browser response.

### Build

`build.py` is outside the runtime artifact. It parses runtime imports, checks the standard-library set and empty manifest, executes tests, builds two in-memory zipapps, compares bytes, and writes the artifact plus proof.

## Complexity

| Operation | Time | Additional memory |
| --- | --- | --- |
| File hashing | `O(n)` | `O(1)` streaming buffer |
| Directory inspection | `O(total bytes + entries)` | report metadata per file/finding |
| Duplicate grouping | `O(files)` after hashes | one hash/size entry per file |
| ZIP/TAR inspection | `O(members)` plus bounded nested reads | archive metadata and bounded nested member |
| JPEG/PNG cleaning | `O(file bytes)` | one segment/chunk at a time |
| OOXML cleaning | `O(package bytes)` | one ZIP member at a time, except `ZipFile.read` for each member |
| Bundle creation | `O(total bytes)` | metadata per file plus fixed streaming buffer |
| Capsule creation | `O(total bytes)` | manifest/ledger per file plus fixed Base64 buffer |
| CLI capsule verification | `O(HTML bytes + payload bytes)` | full HTML and JSON plus a decoded payload; 128 MiB HTML limit |
| Parity creation | `O(file bytes)` | `O(chunk_size)` |
| Recovery | `O(file bytes)` | `O(stripe_width * chunk_size)` |

Bundle and capsule inputs are streamed in fixed-size blocks. Embedded manifests and reports are held in memory and grow with the scan result. A recipient browser retains the full HTML and parsed Base64 data. Checks decode payloads sequentially without caching decoded files, but temporary byte arrays and download blobs require additional memory. Total browser memory is not constant in handoff size.

## Why Python

Python's standard library provides binary structures, archive codecs, XML, Base64, hashing, HTTP, cookies, concurrency, tests, and zipapp construction in one runtime. The implementation still has to supply the security policy, file-format logic, deterministic rules, capsule format, transformation ledger, parity format, three browser interfaces, and request handling that packages normally hide.
