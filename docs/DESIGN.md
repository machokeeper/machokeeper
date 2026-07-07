# Design: the doors

machokeeper exists because a Nix store-path hash rewrite (or a producer
bug like `bun --compile`) can leave a signed Mach-O binary with page
hashes that no longer match its bytes. macOS kills such a binary at
first page-in with `SIGKILL` (`cs_invalid_page`). See the [README](../README.md)
intro and [NixOS/nixpkgs#507531](https://github.com/NixOS/nixpkgs/issues/507531),
[NixOS/nix#6065](https://github.com/NixOS/nix/issues/6065).

The design is organized around a single question: **by which doors do
stale-signature bytes enter a store, and what guards each door?** Every
door has one mechanism; together they cover the paths a binary can take
from "produced" to "executed" without ever running a patched daemon.

## The C++ ancestor, and why this is out-of-band

The engine is a port of the C++ repair validated on the
[NixOS/nix#15638](https://github.com/NixOS/nix/pull/15638) branch, which
repairs signatures **inline in the daemon** as bytes are committed to
the store (`addToStore` / `registerValidPath`). That is transparent —
every path entering the store is covered, whoever triggered it — but it
requires running a patched `nix-daemon`.

machokeeper deliberately does **not** patch the daemon. It uses only
documented plumbing (`nix-store` CLI, standard hooks), so it installs as
an ordinary module with no daemon fork, no `trusted-users` change, and
no signing keys. The cost of staying out-of-band is that there is no
single inline choke point; instead each door is guarded by the
mechanism appropriate to it. Nix offers **no post-substitution hook**
(`post-build-hook` fires only after *local builds*, never after a
substitution/`nix copy`), and patching the daemon is the only way to run
code inline on every substituted path — so the substitution door is
guarded by wrapping the command that triggers it, not by a hook.

## The doors

| Door | When stale bytes appear | Guard | Entry point |
|---|---|---|---|
| **Local build** | a derivation is built locally and its output's signature is stale (partial-store rewrite, producer bug) | **post-build hook** — repairs `$OUT_PATHS` before the output is first used | `machokeeper post-build-hook` |
| **System rebuild** | `darwin-rebuild switch` / `nixos-rebuild switch` substitutes binaries into the new generation | **activation scan** — repairs the new generation's closure delta after substitution, before the generation goes live (so a broken `fish` never becomes your login shell) | `machokeeper scan-generation` |
| **Ad-hoc substitution** | `nix build`/`shell`/`run` substitutes a binary from a cache and uses it in the same invocation (e.g. `direnv`'s check phase running a just-fetched `fish`) | **wrap** — dry-runs the command, repairs what it would substitute, then runs it unmodified; a failed run is retried once after repairing what it pulled | `machokeeper wrap -- <nix cmd>` |
| **Already-broken store** | the store already contains stale binaries when machokeeper is first enabled, or a rooted path (login shell) is broken | **doctor / first-enable sweep** — scan and repair on demand; a one-time whole-store sweep on first enable | `machokeeper doctor [--fix\|--fix-live]`, `machokeeper sweep` |

### Why `wrap` is the substitution door

Because Nix has no post-substitution hook, the only out-of-band way to
catch a binary that is *substituted and then immediately executed within
one command* is to wrap that command: ask Nix (via a dry run) what it
would fetch, realise and repair those paths first, then run the real
command unmodified. This is best-effort by design — the dry-run list can
diverge from what a run actually pulls (import-from-derivation, impure
evaluation) — so a failed run is retried once after a repair sweep of
what it did pull. `wrap` needs no proxy and no signing keys.

The build and system-rebuild doors are guarded automatically by the
module; **the ad-hoc substitution door is the only one that needs `wrap`
around the command.** For interactive use this can be made transparent
with a shell alias/function that routes `nix` through `machokeeper wrap
-- nix` (see the module's shell-integration option).

## Relationship to the in-daemon patch

The out-of-band doors cover the same paths as the in-daemon patch, with
one behavioral difference: the daemon patch is transparent at the
substitution door (any process is covered), while machokeeper guards
that door by wrapping the command. So:

- **Build and system-rebuild doors** are covered automatically and are a
  drop-in replacement for the patch's coverage of those paths.
- **The ad-hoc substitution door** needs `wrap` (or a shell wrapper that
  applies it transparently). Without that, an ad-hoc `nix run` of a
  freshly-substituted darwin binary that is executed immediately is the
  one case the patch catches inline that machokeeper does not — unless
  the command was wrapped.

A periodic sweep can catch substituted paths shortly after they land,
but "eventually" is not "inline": a binary could be page-in-killed once
before the sweep reaches it. The sweep is therefore a safety net, not a
substitute for `wrap` at the substitution door.

## What is out of scope

- **Content-addressed cold-build corruption** ([#6065](https://github.com/NixOS/nix/issues/6065))
  — detected only; no consistent repair exists (repairing would break
  the content address). See [THREAT-MODEL.md](../THREAT-MODEL.md).
- **`--check` / `--rebuild` spurious nondeterminism** — happens inside
  Nix at build time, not reachable from an out-of-band tool.
- **Developer-ID / App Store (CMS) signatures** — detected, never
  touched; only the original signer can regenerate them.

## Invariants

The repair-scope invariants (only stale hash slots rewritten; journaled
byte-exact undo; re-verify after repair; never CMS/Developer-ID; never
content-addressed paths) live in [CONTRIBUTING.md](../CONTRIBUTING.md)
and [THREAT-MODEL.md](../THREAT-MODEL.md), and are enforced by the
engine and the doctor, not by convention.
