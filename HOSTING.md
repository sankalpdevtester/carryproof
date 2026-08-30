# Public demo

Live: <https://carryproof-sage.vercel.app/>

The hosted demo is a static export of a real CarryProof capsule, not the private
LAN server. It contains only synthetic fixtures and reviewed release artifacts.
It needs no access code, account, upload, API, or database.

The five-step walkthrough opens on load. Judges can dismiss it, replay it with
**Walkthrough**, or jump to a step. Verification, the one-byte test, and individual
downloads call the capsule's existing functions. The progress labels reflect
actual results from that verifier, not timers or prerecorded answers.

## Build and preview

```console
python build.py
python demo/build_site.py
python -m http.server 8766 --bind 127.0.0.1 --directory dist/demo
```

Open <http://127.0.0.1:8766>. Python 3.11+ and a current browser are sufficient.
The build uses temporary synthetic input, so existing personal folders and local
demo sessions cannot accidentally become public assets. Tests check the exact
exported file list, checksums, real capsule/ZIP verification, and reproducibility.

## Hosting

Upload the contents of `dist/demo` to a static HTTPS host. There is no install or
framework build step. The included `vercel.json` adds restrictive headers and
download filenames when deployed on Vercel; any ordinary static HTTPS host can
serve the same HTML, JSON, ZIP, and Python archive files.

For an already installed and authenticated Vercel CLI:

```console
vercel link --cwd dist/demo --project carryproof --yes
vercel deploy --cwd dist/demo --prod --yes
```

The publishing CLI is an optional external deployment tool, not a project build
or runtime dependency. It is not bundled, imported, or required by CarryProof.
No `npm install` or `pip install` is part of the application or demo build.

The export's `.vercelignore` is an explicit upload allowlist. Local environment
files, project credentials, logs, and source folders are never in that list.

The hosted sample does not accept uploads or run Python on a remote server.
Scanning, sanitization, CLI verification, recovery, and private LAN sharing run
locally in the downloadable executable. Never expose a `serve --demo` instance
containing personal files to the public internet.

## Files and trust

`sample.carryproof.html` is the unmodified offline capsule. The walkthrough is
added only to `index.html`; it is not required by recipients or the core runtime.
`SHA256SUMS.txt` covers both pages and the downloadable artifacts. Checksums served
beside files confirm consistency, but are not an independent trust channel.

The JPEG/Office samples are structural parser fixtures, not complete end-user
documents. The page discloses this and uses a text file for its extraction step.
Opening downloaded HTML directly still depends on the recipient browser's local
file policy. A successful hosted test does not establish that offline launch was
tested in that browser.
