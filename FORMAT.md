# CarryProof formats and guarantees

## Proof-carrying HTML capsule

`<input>.carryproof.html` is a deterministic standalone browser application containing only prepared file payloads. It has three logical sections:

1. A canonical JSON manifest in the `capsule-manifest` data island.
2. An ordered JSON payload array in the `capsule-files` data island, with file bytes encoded as Base64.
3. Static HTML/CSS/JavaScript that verifies and extracts payloads without a network request.

Manifest fields include:

| Field | Meaning |
| --- | --- |
| `kind` | `proof-carrying-handoff`. |
| `source_name` | Non-absolute input identity. |
| `original_summary` / `prepared_summary` | Before/after risk and finding counts. |
| `transformations` | Original/prepared paths and hashes, byte sizes, changed flag, and recorded actions. |
| `files` | Ordered prepared paths, sizes, detected types, download MIME policy, and SHA-256 hashes. |

Canonical JSON uses UTF-8, sorted object keys, compact separators, and one final newline. `<` is serialized as `\u003c` before entering the HTML script data island. The **content seal** is SHA-256 over those exact serialized bytes. `carryproof-capsule.json` publishes the same metadata plus the seal and whole-capsule hash for machine use.

Payload order matches manifest file order. During creation, each file is streamed through Base64 in blocks divisible by three, so output does not depend on read boundaries. Volatile timestamps and absolute paths are excluded.

The browser verifier performs this sequence:

1. SHA-256 the exact manifest text and compare it with the embedded content seal.
2. Base64-decode a requested payload.
3. Compare decoded length and SHA-256 with the corresponding manifest entry.
4. Create a local `application/octet-stream` download only after both comparisons succeed.

The seal covers only the manifest, not the verifier code or surrounding HTML. It is integrity metadata, not a signature. An external trusted **whole-capsule SHA-256** is required to check the entire artifact before opening it. Capsule payloads are encoded, not encrypted, and may include unchanged files with unresolved findings.

`carryproof verify capsule.html` parses the data islands without executing scripts. It rejects duplicate islands, noncanonical manifests, unsafe or duplicate paths, invalid Base64, mismatched inventory, sizes, and hashes. `--sha256 EXPECTED_HASH` additionally compares the complete HTML bytes with an independently obtained hash. The verifier has a 128 MiB HTML input limit.

The capsule's **Test one-byte change** control changes one byte of a temporary decoded copy and uses the same payload comparison as real downloads. It never modifies embedded data or writes a damaged artifact. It demonstrates detection, not sender authentication.

## Deterministic bundle

A CarryProof bundle is a ZIP64-compatible archive using DEFLATE from `zipfile`.

Determinism rules:

- Entries are sorted by POSIX-style relative path.
- Entry timestamps are fixed to `1980-01-01 00:00:00`, the ZIP epoch.
- File permissions are normalized to `0644`.
- Compression method and level are fixed.
- JSON uses sorted keys, compact separators, UTF-8, and a final newline.
- Volatile report timestamps are omitted from copies embedded in the bundle.

Reserved entries:

| Entry | Purpose |
| --- | --- |
| `CARRYPROOF-MANIFEST.json` | Paths, sizes, SHA-256 hashes, tool version, and before/after summaries. |
| `CARRYPROOF-REPORT.json` | Machine-readable original and prepared inspections without volatile timestamps. |
| `CARRYPROOF-REPORT.html` | Standalone interactive report. |

`carryproof verify` validates the manifest schema and exact payload inventory, checks ZIP CRCs, then streams every listed file through SHA-256. Unsafe or duplicate paths, reserved-name collisions, missing or extra payloads, invalid sizes, and hash mismatches fail. Expanded data is limited to 2 GiB, payload count to 100,000, and manifest size to 32 MiB.

Report entries are checked by ZIP CRC but are not included in the payload hash manifest. Supply a trusted `--sha256` of the complete ZIP to cover the reports and manifest as well. Reproducibility is tested with the same Python/compression runtime; byte-identical DEFLATE output across all zlib versions is not promised.

## `.cproof` recovery sidecar

All integer fields outside JSON are unsigned big-endian.

```text
offset  size  value
0       6     ASCII/binary magic: CPRF1\0
6       8     JSON header length N
14      N     UTF-8 deterministic JSON header
14+N    ...   consecutive XOR parity payloads, one per stripe
```

Header fields:

| Field | Meaning |
| --- | --- |
| `schema` | Header schema version, currently `1`. |
| `algorithm` | `xor-stripe-v1`. |
| `source_name` | Informational original basename. |
| `file_size` | Exact original byte length. |
| `file_sha256` | Whole-file SHA-256. |
| `chunk_size` | Maximum bytes in one data chunk. |
| `stripe_width` | Maximum data chunks covered by one parity chunk. |
| `chunk_hashes` | Ordered SHA-256 hash for every data chunk. |
| `parity_sizes` | Ordered byte length of each parity payload. |

### Encoding

For each stripe, the encoder XORs corresponding byte positions from every data chunk. Short final chunks behave as if padded with zero bytes. The parity payload length equals the longest data chunk in that stripe.

### Recovery

The decoder hashes every source chunk and compares it with `chunk_hashes`.

- Zero bad chunks: source chunks are copied after verification.
- One bad or missing chunk: parity is XORed with every good chunk to reconstruct it.
- Two or more bad chunks: recovery fails for that stripe.

The decoder writes to a temporary sibling file. It publishes the result only after every reconstructed chunk hash and `file_sha256` match. A failed recovery leaves no destination file.

### Guarantee

CarryProof repairs at most one missing or corrupted chunk per stripe. This is not Reed-Solomon and provides no Byzantine protection or authenticity. Choose a smaller stripe width for more parity overhead and smaller correlated-failure domains.

Approximate parity overhead is `1 / stripe_width`, excluding the hash header. With the default width of 8, payload overhead is about 12.5%.

## Inspection report schema

Top-level report output contains `original` and, after cleaning, `prepared` objects. Each inspection includes:

- `schema`, tool, version, generation time, and non-absolute source identity.
- Summary status, risk score, byte/file counts, findings, and duplicate space.
- Findings with severity, stable code, relative location, message, detail, and remediation.
- File inventory with relative path, size, SHA-256, detected type, MIME presentation type, metadata names, duplicate reference, and cleaning actions.
- Duplicate groups keyed by SHA-256.

Absolute source paths and matched secret values are intentionally excluded.

## Status and process exits

| Status | Meaning |
| --- | --- |
| `clear` | No medium, high, or critical findings. |
| `caution` | At least one medium finding, no high or critical findings. |
| `review` | At least one high finding, no critical findings. |
| `blocked` | At least one critical finding. |

`scan`, `clean`, and `prepare` return exit code `3` for `review` or `blocked`. They still produce outputs so automation can preserve evidence and request human review. The status is not enforced quarantine, and a prepared artifact can contain files with findings. Risk scores are capped sums of severity weights, not probabilities. `verify` returns `4` for a failed integrity check.
