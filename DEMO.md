# Five-minute demo script

## Public judge walkthrough

Open [the live demo](https://carryproof-sage.vercel.app/). The walkthrough opens
automatically and has five steps: the handoff, recorded changes, file verification,
one-byte corruption rejection, and verified extraction. It can be dismissed or
replayed with **Walkthrough**. The hosted sample is public and needs no login or
access code. Its controls use the real embedded verifier.

The recording workflow below additionally demonstrates the local Python runtime
and private LAN portal. That portal deliberately displays a code in demo mode.

The demo uses generated synthetic fixtures, not private user files. Its JPEG and OOXML inputs exercise parsers and metadata transformations; they are not representative full photographs or Office documents. Use the PNG or text payload to demonstrate downloading. The judge access code is intentionally public only for this run.

## Before recording

```console
python build.py
python demo/make_demo.py --overwrite
python dist/carryproof.pyz prepare demo/generated/inbox --overwrite
python dist/carryproof.pyz serve demo/generated/inbox-carryproof --host 127.0.0.1 --port 8765 --code 12345678 --demo --ttl 10m
```

Open [the local demo](http://127.0.0.1:8765). Keep `requirements.txt`, `deps-proof.txt`, and a terminal ready. Read the limitations before recording; do not describe a matching hash as a malware verdict or a signature.

Before claiming an offline launch in the video, manually open the generated capsule as a local HTML file in the intended browser with the network disconnected, verify its payloads, and download a text file. Automated browser checks covered the localhost version; direct local-file navigation was unavailable in the embedded browser.

## 0:00-0:25 - Start with the recipient

Show the login page. The page itself says **Judge demo code: 1234 5678**. Select **Use code**, then **Unlock handoff**.

The dashboard immediately shows the real result from the generated report:

- heuristic score `75 -> 5`, not a percentage likelihood;
- five fewer findings;
- six prepared files;
- recovery data ready.

Say:

> CarryProof makes the handoff its own receiver application. Prepared bytes, a record of what changed, and an integrity verifier travel in one HTML file. The recipient does not have to install this tool.

## 0:25-1:35 - Verify, then challenge the artifact

Select **Open offline capsule**. Point out that this is the generated `inbox.carryproof.html`, not the running portal UI.

Show:

- the manifest SHA-256, initially marked `Not checked`;
- before and prepared heuristic scores;
- prepared payloads initially marked `Not checked`;
- recorded transformations, including EXIF removal and `.docm -> .sanitized.docx`;
- an expanded **Fingerprints** row comparing original and prepared hashes.

Select **Verify all payloads**. Wait for all six rows to become `Verified`. Select **Test one-byte change** and show the rejection result. Explain that this changes a temporary in-memory copy and calls the same hash comparison used for downloads. Verify all again to show that embedded files were not modified.

Say:

> A one-byte difference fails the real comparison. Each download checks the manifest and requested payload before creating a local download. The unmodified capsule needs no network requests, but matching hashes say nothing about whether its contents are safe to open.

Download `notes.txt` or `image-with-author.png`. Explain that this localhost view tests the generated capsule's browser interface; it is not proof of having launched a downloaded file offline. Browser policies differ, and ordinary LAN HTTP may lack Web Crypto.

The manifest seal excludes the verifier code. A sensitive recipient must first compare the complete HTML file hash through a trusted separate channel. The CLI can do that without executing its scripts:

```console
python dist/carryproof.pyz verify demo/generated/inbox-carryproof/inbox.carryproof.html --sha256 TRUSTED_WHOLE_FILE_HASH
```

## 1:35-2:20 - Show the recorded evidence

Return to the dashboard and select **Inspect before / after**. Toggle **Original** and **Prepared**.

Show:

- image GPS/author metadata disappearing;
- Office authorship, macro, and external relationship findings disappearing;
- `.docm` becoming `.sanitized.docx`;
- visible email/IP findings remaining for human review rather than being silently rewritten.

Show `demo/generated/inbox` beside `demo/generated/inbox-carryproof/cleaned` and point out that originals were not modified.

## 2:20-2:55 - Prove zero dependencies

Show the empty `requirements.txt`, then run:

```console
python build.py --skip-tests
```

Point to:

- `Third-party runtime imports: 0`;
- two byte-identical build hashes;
- the single `dist/carryproof.pyz` runtime artifact.

Say that the normal build runs 40 standard-library tests, including altered payloads and manifests, changed verifier code, exact ZIP inventory, filename collisions, reproducibility, HTTP authentication, and recovery.

## 2:55-3:35 - Flag hostile inputs

```console
python dist/carryproof.pyz scan demo/generated/hostile --html demo/generated/hostile-report.html --output demo/generated/hostile-report.json
```

The intentional exit code is `3`. Show the executable signature disguised as `invoice.txt`, ZIP parent traversal, and bomb-like compression ratio. This is an automation stop signal, not a crash or enforced quarantine. A `prepare` run can still produce artifacts containing unchanged files with findings; the caller must honor the review signal.

## 3:35-4:25 - Survive damaged transport

```console
python demo/damage.py demo/generated/inbox-carryproof/inbox.carryproof.zip demo/generated/inbox-carryproof/inbox.damaged.zip
python dist/carryproof.pyz recover demo/generated/inbox-carryproof/inbox.damaged.zip demo/generated/inbox-carryproof/inbox.carryproof.zip.cproof --output demo/generated/inbox-carryproof/inbox.recovered.zip
python dist/carryproof.pyz verify demo/generated/inbox-carryproof/inbox.recovered.zip
```

Show one repaired chunk, the final SHA-256, and successful verification of the ZIP inventory and payload hashes. State the boundary precisely: XOR parity repairs one bad chunk per stripe and refuses two; it is not Reed-Solomon.

## 4:25-5:00 - Close on the installable idea

Show `carryproof.py`, the empty manifest, and `STDLIB.md`.

Say:

> The useful unit is the handoff: prepared files, original fingerprints, recorded transformations, verifiable payloads, and optional repair data. The output is its own receiver application. One runtime source file, the Python standard library, native browser APIs, and no third-party runtime packages.

End on the capsule with **All payloads verified** visible.
