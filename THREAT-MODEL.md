# Threat model

machokeeper parses attacker-influenceable bytes (store files come from
builders and substituters) and mutates the Nix store, sometimes as root.
This document says what we defend against, how, and what is out of
scope. For the architecture — the "doors" stale bytes enter a store by
and the mechanism guarding each — see [docs/DESIGN.md](docs/DESIGN.md).

## Assets

1. The integrity of the Nix store: files and the database rows
   describing them.
2. The host: machokeeper must not be a privilege-escalation or
   code-execution vector.
3. The trust chain: a repaired path must never silently masquerade as
   something a substituter signed.

## Attacker-controlled inputs

| Input | Source | Exposure |
|---|---|---|
| Mach-O bytes | untrusted builders, substituters | parsed by the engine |
| Store paths / file names | command line, hooks, closures | path handling |
| `OUT_PATHS` | the nix daemon (trusted) via post-build-hook | path list |
| nix log output (`wrap`) | the local nix binary (trusted) | parsed heuristically |

## Defenses, by asset

### Host: parsing untrusted bytes

- The engine is ~600 lines of bounds-checked slice arithmetic with no
  allocation proportional to attacker-chosen fields, no I/O, and no
  unsafe. Every multi-byte read is explicitly bounds-checked against the
  buffer; walk lengths (fat arches, SuperBlob entries, CodeDirectories)
  are capped.
- Memory safety is enforced by Go; logic safety is fuzzed continuously
  (`FuzzDetect`, `FuzzCheck`, `FuzzRepair` — no panic, check never
  mutates, repair preserves length) and cross-validated against an
  independent Python verifier that shares no code with the engine.
- The tool executes only `nix-store`/`nix` from `PATH` with
  fixed argument shapes; no shell interpolation anywhere.

### Store integrity

- Repairs are slot-surgical and journaled; `machokeeper undo` restores
  byte-exact state. A repair that fails re-verification is discarded.
- Hardlink safety: repaired bytes are written to a sibling temp file and
  renamed over the original, so an `auto-optimise-store` inode shared
  with other paths is never written through — only this path's directory
  entry is repointed.
- Database coherence: after a repair the path's hash row is
  reconciled in place via `--register-validity --reregister
  --hash-given` with the recomputed NAR hash (export/delete/import is
  not viable: `nix-store --export` verifies the recorded hash before
  streaming, so it always refuses a just-repaired path). The path keeps
  its name; input-addressed store paths do not depend on their
  contents. Rooted paths additionally require `--fix-live` — the
  distinction is operator consent to touch a live path, not mechanism.
- Refusal classes: Developer-ID (CMS) signatures and content-addressed
  paths are reported, never written to.

### Trust chain

- machokeeper never forges signatures. Re-registration drops any
  substituter signatures that covered the old bytes; a repaired path is
  registered unsigned, and a store that requires signatures will treat
  it accordingly.
- The substituter's original artifact is never re-served: repair is
  strictly local.

## Residual risks (accepted, documented)

- **A repaired path diverges from the cache.** `nix store verify`
  against the substituter will report a hash mismatch for a repaired
  path, and `nix store verify --repair` would restore the broken cached
  copy. The undo journal doubles as the record of repaired paths.
- **`--fix-live` reconciles the database while the daemon may be
  running.** The register-validity call is a normal daemon operation,
  but a concurrent operation on the same path during the reconcile
  window is not excluded by machokeeper itself. If in doubt, prefer
  `--fix` from a context where the path is unrooted.
- **`wrap`'s log parsing is heuristic.** internal-json is not a stable
  interface; wrap treats its pre-fetch list as best-effort and falls
  back to repair-and-retry-once. A missed path degrades to the failure
  the user would have had anyway.
- **Single-user (non-daemon) installs run the parser at the invoking
  user's privilege**, which for root-owned stores means root. This
  matches every other tool on such installs; the engine's fuzzing and
  bounds discipline are the mitigation.

## Out of scope

- Repairing what cannot be repaired: Developer-ID signatures (only the
  signer can), content-addressed self-references (no consistent hash
  exists — NixOS/nix#6065).
- Defending against a malicious *nix* or *nix-store* binary on PATH, a
  compromised daemon, or a hostile root user: machokeeper trusts the
  Nix installation it operates.
- The `--check`/`--rebuild` code path inside Nix, which no external tool
  can reach.
