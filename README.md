# machokeeper

[![CI](https://github.com/machokeeper/machokeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/machokeeper/machokeeper/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/machokeeper/machokeeper)](https://goreportcard.com/report/github.com/machokeeper/machokeeper)

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

## Repairing store paths

`doctor --fix` repairs a registered store path safely. It writes each repaired file to a sibling temp and renames it into place, so a file that `auto-optimise-store` hardlinks across paths is not corrupted through its other names, and it reconciles the path's recorded NAR hash in place with `nix-store --register-validity --reregister --hash-given` so the database matches the repaired bytes (the path keeps its name — input-addressed paths do not depend on their contents). Repair may need `sudo` on a multi-user install; doctor prints the operations before it runs them.

A path that is a GC root or referenced by another path (a live login shell) is in use, so `--fix` refuses it. `doctor --fix-live` is the explicit consent to repair such a live path; the repair and hash reconciliation are the same. Use it when your shell itself is broken.

## Continuous protection (module)

machokeeper guards every *door* stale-signature bytes enter a store by —
local build, system rebuild, ad-hoc substitution, already-broken store —
each with one mechanism, and none requiring a patched daemon. The full
model is in [docs/DESIGN.md](docs/DESIGN.md).

For nix-darwin, NixOS, or home-manager, enable the module and the build
and system-rebuild doors are guarded automatically — no daemon, no timer
(the ad-hoc substitution door is guarded by [`wrap`](#ad-hoc-commands-wrap)):

```nix
{
  inputs.machokeeper.url = "github:machokeeper/machokeeper";

  # nix-darwin:
  imports = [ inputs.machokeeper.darwinModules.default ];
  services.machokeeper.enable = true;
}
```

- **`post-build-hook`** repairs locally built outputs before first use (the partial-store rewrite trigger). Nix allows only one post-build-hook, so machokeeper **auto-detects and chains** any existing `nix.settings.post-build-hook` (e.g. a cachix push hook) — you change nothing but `enable`. Add further hooks with `services.machokeeper.extraPostBuildHooks = [ … ];`.
- **Activation scan** repairs the new generation's store paths during `darwin-rebuild switch` / `nixos-rebuild switch`, after substitution and before the generation goes live — so a broken `fish` never becomes your login shell. Set `services.machokeeper.onActivation = "refuse";` to fail the switch instead of repairing.
- **First-enable sweep** repairs anything already broken in the store, once.

On **home-manager** the module installs the CLI and, on activation, scans your profile read-only and warns if anything is broken — repair itself needs write access to the store, so use the nix-darwin/NixOS module (or `sudo machokeeper doctor --fix`). `post-build-hook` is a trusted daemon-side setting a user-level nix.conf can't set on a multi-user install, so it's wired by the system module, not home-manager.

## Ad-hoc commands (wrap)

For `nix build`/`shell`/`run` that both substitute and use a binary in one invocation (like `direnv`'s check phase running a just-fetched `fish`):

```console
$ machokeeper wrap -- nix build .#something
```

It dry-runs the command, repairs what would be substituted, then runs the command unmodified; a failed run is retried once after repairing what it pulled. No proxy, no signing keys, no `trusted-users` change.

## Coverage

| Case | machokeeper |
|---|---|
| Broken binaries substituted from cache (fish, and the [~440 tracked slices](https://github.com/ak2k/nix-507531-scope)) | repair — `doctor`, wrap, activation scan |
| Builds failing on a broken substituted dependency (direnv's `fish` check phase) | fixed — the dependency is repaired first |
| Already-broken store, including a rooted login shell | repair — `doctor --fix` / `--fix-live` |
| Local build rewrite damage (partial store state) | repair — `post-build-hook`, before first use |
| Developer-ID / App Store signatures | detected, never touched (signer-only) |
| Content-addressed cold-build corruption ([#6065](https://github.com/NixOS/nix/issues/6065)) | detected only — no consistent repair exists |
| `--check` / `--rebuild` spurious nondeterminism | not reachable — happens inside Nix at build time |

The last two are inside Nix and remain upstream work; everything else machokeeper detects, and repairs where a repair exists.

## License

MIT
