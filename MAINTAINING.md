# Maintaining netcheck

This is the maintainer runbook: publishing the repo and cutting releases. For
operator usage, see [`USAGE.md`](USAGE.md).

## Repository layout

```
netcheck/
├── netcheck.py                     # the entire CLI (single file, stdlib only)
├── netcheck.ini.example            # config template (safe to commit)
├── USAGE.md                        # operator guide
├── MAINTAINING.md                  # this file
├── .github/workflows/release.yml   # tag -> release assets + SHA256SUMS
├── tests/                          # unittest suite (stdlib)
├── docs/superpowers/               # design specs and implementation plans
├── idea.md                         # original requirements
├── DGS-1210-28_REVC_MANUAL_4.00_EN.md   # switch manual (reference)
└── DGS-1210-28-CX-4-00-008.mib          # switch MIB (reference)
```

## Tests

Run the full suite before tagging:

```bash
python3 -m unittest discover -s tests -v
```

All tests must pass. The suite is standard-library `unittest`; it needs no
dependencies.

## Secrets — never commit

These are gitignored and must stay that way:

- `netcheck.ini` — the real config, including the SNMP community and any
  credentials.
- `netcheck-*.log` — run logs, which can include network detail.
- `SHA256SUMS` — generated at release time, not stored in the repo.
- `.superpowers/` — local agent scratch workspace.

The example file `netcheck.ini.example` is safe to commit (no secrets).

## First-time publish to GitHub

1. **Create an empty public repo** on github.com named `netcheck`
   (no README, no `.gitignore`, no license — history already exists), or with
   the GitHub CLI:

   ```bash
   gh repo create CountElqyd/netcheck --public --source=. --remote=origin
   ```

2. **Add the remote and push** (skip if `gh` already did it):

   ```bash
   git remote add origin https://github.com/CountElqyd/netcheck.git
   git branch -M main
   git push -u origin main
   ```

## Cutting a release

Releases are driven by tags. Pushing a `v*` tag triggers
`.github/workflows/release.yml`, which builds `SHA256SUMS` from `netcheck.py`,
`netcheck.ini.example`, and `USAGE.md`, and attaches all four files to a GitHub
Release.

```bash
git tag v0.1.0
git push origin v0.1.0
```

Recommended sequence for a version bump:

1. Make sure `main` is green (`python3 -m unittest discover -s tests`).
2. Tag and push:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. Confirm the release and assets appear under **Releases** on GitHub. The
   download links in [`USAGE.md`](USAGE.md) §6.2 point at
   `releases/latest/download/`, so they resolve automatically once a release
   exists.

## Changing the tool

- `netcheck.py` is the whole program; keep it single-file and standard-library
  only. Optional features (scapy, pysnmp) are opt-in extras, never hard
  dependencies.
- Keep the tool **read-only** against switches and the router: no SNMP SET, no
  CLI `config`/`save`, no router changes.
- New behavior needs tests under `tests/` and a docs update in `USAGE.md`.
