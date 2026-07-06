# Security

## Reporting a vulnerability

Report privately via [GitHub security advisories](https://github.com/machokeeper/machokeeper/security/advisories/new).
You should hear back within a week. Please do not open public issues for
suspected vulnerabilities in the repair path.

## What this tool is trusted to do

machokeeper modifies files in the Nix store and, in its module form,
runs during builds and system activation — often as root. The design
constrains that trust:

- **The parser never runs with privilege it doesn't need.** All parsing
  of untrusted bytes happens in the invoking process; the engine does no
  I/O of its own, and the tool holds no daemon, listener, or long-lived
  state.
- **Repair writes only stale hash slots.** The engine recomputes
  CodeDirectory page hashes and touches no other byte; every write is
  recorded `(file, offset, old-bytes)` in an undo journal for byte-exact
  reversal. Length is always preserved.
- **Repair is re-verified before it counts.** A repaired file must pass
  the engine's own check (and, in CI, an independent from-scratch Python
  verifier and Apple's `codesign`) or it is not committed.
- **Store metadata is updated only through documented plumbing** —
  `nix-store --export/--import` and `--register-validity` — never by
  writing to the database directly.
- **Detection is the default.** Nothing is modified without `--fix`,
  `--fix-live`, or the module's explicit `enable` (which is the consent).
- **Fail open in hooks.** The post-build hook and activation scan always
  exit 0: machokeeper can never make a build or switch fail that would
  otherwise have succeeded (unless the operator opts into
  `onActivation = "refuse"`).
- Developer-ID/App-Store-signed files and content-addressed paths are
  never modified.

See [THREAT-MODEL.md](THREAT-MODEL.md) for the analysis behind these
choices.

## Verifying releases

Release binaries are built reproducibly (`CGO_ENABLED=0`, `-trimpath`)
by GitHub Actions from the tagged commit, with:

- `SHA256SUMS` alongside every asset,
- SLSA build provenance attestations
  (`gh attestation verify <asset> --repo machokeeper/machokeeper`),
- an SPDX SBOM.

Installing via the flake (`nix run github:machokeeper/machokeeper`)
builds from source and pins the exact revision by hash.
