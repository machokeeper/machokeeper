# machokeeper

Keep your Nix store's Mach-O binaries valid.

On macOS, a binary only runs if its code signature's page hashes match its contents — the kernel kills it at first page-in otherwise (`Killed: 9`, `cs_invalid_page`). Nix stores accumulate binaries that fail this check: store-path hash rewriting damages signatures during builds ([NixOS/nixpkgs#507531](https://github.com/NixOS/nixpkgs/issues/507531), [NixOS/nix#6065](https://github.com/NixOS/nix/issues/6065)), and producer bugs ship pre-broken artifacts through cache.nixos.org ([tracking scanner](https://github.com/ak2k/nix-507531-scope)). macOS 27 tightens enforcement: binaries that still run today become launch-fatal.

machokeeper detects these, explains them, and repairs the repairable ones.

## Quick start

```console
# Diagnose a binary that gets Killed: 9, or any path:
$ nix run github:machokeeper/machokeeper -- doctor /nix/store/...-fish-4.2.1
BROKEN  /nix/store/...-fish-4.2.1/bin/fish  [repairable]

# Scan your whole store:
$ nix run github:machokeeper/machokeeper -- doctor --scan

# Repair (writes a byte-exact undo journal):
$ nix run github:machokeeper/machokeeper -- doctor --fix /nix/store/...-fish-4.2.1
```

## What repair does — and never does

Repair recomputes only the stale page-hash slots inside the signature, in place. Every other byte is preserved: the `linker-signed` flag, the page size, the identifier, the CMS wrapper. Same input bytes always produce the same output bytes, and every write is journaled `(file, offset, old-bytes)` for byte-exact undo.

Never repaired, only reported:

- **Developer-ID / App Store signatures** — the certificate chain commits to the CodeDirectory; only the signer can fix these.
- **Content-addressed store paths** — repairing would break the path's content address.

A signature the engine cannot verify (unsupported hash type, malformed CodeDirectory, zero CodeDirectories) is treated as broken, never waved through.

## Correctness

The engine is a port of the repair validated on the [NixOS/nix#15638](https://github.com/NixOS/nix/pull/15638) branch: unit-tested against hand-built byte fixtures, mutation-fuzzed, and cross-validated in CI against an independent from-scratch Python verifier that shares no code with it. The original was verified 10/10 against real broken cache.nixos.org binaries spanning every failing signature class (thin, fat32/fat64, dual SHA-1+SHA-256 CodeDirectories, 56-slot Bun single-file executables).

## What it cannot fix

Content-addressed cold-build corruption (NixOS/nix#6065) and the spurious `--check` nondeterminism failure on signed binaries happen inside Nix at build time; no external tool can reach them. They are detected and named, and remain upstream work.

## Roadmap

- `doctor --fix` for registered store paths via `nix-store --export`/`--import` (hardlink-safe, DB-consistent)
- nix-darwin / NixOS / home-manager module: `post-build-hook` + activation-time scan of new generations
- `machokeeper wrap` for ad-hoc `nix build`/`shell`/`run`

## License

MIT
