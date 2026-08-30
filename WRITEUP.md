# I made a file handoff carry its own receiver, with no packages

The unsettling thing about sharing a file is that the visible content is only part of what leaves.

A photograph can carry GPS coordinates and a camera serial number. A document can carry its author, last editor, revision history, macros, embedded objects, and links that contact another server. A ZIP can contain a filename that escapes the directory where it is extracted. A correctly cleaned file can still be corrupted during storage or transfer.

The normal answer is a collection of packages and applications: one for EXIF, another for Office files, another for archive inspection, another for checksums, another for parity, and a web framework when the result needs to reach a phone. The recipient still receives bytes without the evidence that produced them.

For the Zero Dependency hackathon, I built CarryProof using none of them.

## One job, not a toolbox drawer

The first design risk was scope. Combining several useful tools can easily produce a command full of unrelated demos. CarryProof has one workflow instead:

```text
inspect -> sanitize copies -> inspect again -> seal offline capsule -> bundle + repair -> handoff
```

The product question is: "Can the recipient inspect what the sender recorded, verify these exact bytes, and recover from limited transport damage without installing a receiver?" That is narrower than proving the files are safe, which this tool cannot do.

CarryProof identifies a real file type from bytes, computes a streaming SHA-256, examines format-specific privacy and safety structures, creates separate cleaned copies, and scans those outputs again. The before/after report matters. A sanitizer should not receive credit merely because it said it removed something.

The prepared files enter a deterministic offline HTML capsule with their hashes, original fingerprints, and recorded transformations. Every browser download verifies the manifest and requested payload first. A deterministic ZIP supports automation, a `.cproof` sidecar can reconstruct one damaged chunk per stripe, and a read-only authenticated HTTP portal provides a nearby-device handoff.

## The output is its own receiver application

The capsule became the project-defining feature.

`prepare` emits one `.carryproof.html` document. Python streams prepared bytes through Base64, writes a canonical JSON manifest, and computes a seal over its exact serialized bytes. The unmodified HTML makes no network requests. Its payloads come from the prepared directory, which can still include unchanged originals with unresolved risks. The second scan and explicit ledger make that boundary visible; they do not erase it.

When a recipient opens the capsule, its browser uses Web Crypto to hash the manifest again. It then decodes each requested payload, compares byte length and SHA-256, and creates a local download only after both checks pass. The transformation ledger shows which files were byte-preserved, which were rewritten, what was removed, and both sides of every fingerprint change.

This changes the unit of sharing. Instead of sending files and a separate explanation, prepared bytes, recorded evidence, and a receiver travel together. They can be copied by email or USB and inspected in a current Web Crypto-capable browser, subject to browser policy. Localhost supports that API; ordinary LAN HTTP may not. The browser keeps the encoded document in memory, so this is best suited to modest handoffs rather than huge archives.

The most important correction was the trust boundary. A manifest hash does not cover the JavaScript that displays verification results. An attacker could change the code while leaving the manifest intact. A recipient must compare a **whole-file hash obtained through an independent trusted channel** before opening a sensitive HTML handoff. CarryProof's CLI uses `HTMLParser` to inspect data without executing scripts and can check that external whole-file hash first. Tests demonstrate both cases: changed verifier code passes internal payload consistency checks but fails the trusted complete-artifact check. Neither hash is a signature.

The demo makes integrity tangible with a one-byte challenge. It verifies a payload, flips one bit in a temporary copy, and runs the same comparison used for downloads. The changed copy fails; the embedded original is untouched. That is an actual negative test, not a prewritten success animation.

## The standard library was not the hard part

Python already had most of the raw pieces: `struct`, `zipfile`, `tarfile`, `base64`, `hashlib`, `ElementTree`, `http.server`, `secrets`, `unittest`, and `zipapp` behavior.

What packages normally provide is policy and edge handling.

For JPEG, CarryProof walks marker segments and parses enough TIFF IFD structure to identify GPS, ownership, camera, and editing fields. Cleaning removes metadata segments without decoding or recompressing image data.

For PNG, every chunk is length-checked and CRC-verified. Cleaning omits text, XMP, EXIF, and timestamp chunks while copying image chunks unchanged.

Office documents are ZIP containers full of XML and binary parts. CarryProof clears private properties, finds VBA and embedded objects, removes external relationships, converts macro-enabled main content declarations, and rebuilds the package deterministically. Macro-enabled filenames become explicit `.sanitized.docx`, `.xlsx`, or `.pptx` outputs.

Archive inspection never extracts. It evaluates names, links, special entries, member counts, nested archives, expanded size, and compression ratio. A malicious ZIP is evidence, not something the scanner should unpack onto the machine.

## The feature I refused to fake

PDF sanitization is the most important omission.

A correct PDF rewriter needs complete indirect-object parsing, cross-reference handling, filters, object streams, incremental updates, signatures, embedded files, and active actions. Searching for `/Author` and deleting nearby bytes would be easy and irresponsible.

CarryProof scans PDFs for privacy and active-content markers, copies them unchanged, and says exactly that in the report. In a security tool, an honest unsupported operation is a feature.

The same principle applies elsewhere. RAR and 7z are recognized but not decoded because their algorithms are not in the standard library. The browser portal uses HTTP and calls itself trusted-LAN-only because the standard library cannot generate a trusted certificate. XOR recovery data is not advertised as Reed-Solomon.

## Recovery without pretending it is magic

The recovery format was the most enjoyable piece to write.

A file is split into chunks, chunks are grouped into stripes, and each stripe receives one XOR parity chunk. SHA-256 is stored for every data chunk and for the complete file. During recovery, CarryProof identifies corrupted chunks. With one bad chunk in a stripe, XORing parity with every good chunk reconstructs the missing data. With two, recovery stops.

The recovered file is written to a temporary sibling and published only after every chunk hash and the final file hash match. No partial "probably fixed" output appears.

This has a clear mathematical limit and a useful real-world guarantee. The format document says both.

## Making zero dependencies judgeable

An empty `requirements.txt` is necessary but weak evidence by itself.

The build script parses the runtime source with `ast`, collects every top-level import, and checks it against `sys.stdlib_module_names`. It runs the adversarial `unittest` suite, creates the executable zipapp twice with normalized metadata, and compares the bytes. Both SHA-256 hashes and the import list are written to `deps-proof.txt`.

One command checks declared runtime imports, runs 40 tests, and checks reproducibility with the same toolchain. This is inspectable evidence, not a claim that static import analysis alone can establish every possible runtime behavior.

## The edge cases that consumed the time

The obvious implementations usually worked first. The boundaries did not.

- Office macro removal also had to convert the main document content type; deleting every `macroEnabled` declaration would create an invalid package.
- A `.docm` with its macro removed should not keep pretending to be macro-enabled, so prepared outputs need a macro-free extension.
- Office files begin as ZIP signatures, but reporting `.docx` as an extension mismatch before classifying the container creates a false alarm.
- A standalone GZIP stream is not necessarily a compressed TAR archive.
- A static report can become an injection surface when a hostile filename closes a script element.
- A deterministic capsule must stream Base64 in blocks divisible by three or output changes with read boundaries.
- A browser verifier must hash the exact manifest text, including its final newline, rather than a reparsed approximation.
- Every individual download needs the manifest check too; verifying only the file's own hash leaves a gap.
- The manifest seal does not cover the embedded verifier, so whole-artifact trust needs an independent hash check before opening the HTML.
- An embedded HTML report can accidentally reintroduce timestamps into an otherwise deterministic ZIP.
- A macro-free output rename can collide with another input name; silent overwriting is unacceptable.
- A judge demo needs a visible access code, while a real portal must never leak that code without an explicit unsafe demo flag.
- A file-sharing route that joins strings safely can still escape through a symlink unless the resolved final path is checked against the resolved root.
- A recovery implementation must remove its temporary output after a two-chunk failure.

Those are now regression tests.

## What zero dependency changed

The constraint reduced ambiguity. There was no decision about which web framework, EXIF package, Office library, test runner, auth middleware, build packager, or parity binding to choose. The question was whether the standard library exposed enough primitives to build the exact workflow.

It did.

The result is not smaller because every problem disappeared. It is understandable because every layer is visible: file bytes, format structures, safety policy, canonical manifests, hashes, atomic writes, HTTP messages, browser verification code, and build metadata.

CarryProof was built for the Zero Dependency hackathon organized by Hackathon Raptors. The project repository includes the implementation, tests, limitations, format specification, security model, and standard-library substitution ledger. Add the public repository URL before publishing this write-up.
