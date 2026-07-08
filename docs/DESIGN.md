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
module — that is the primary delivery. **The ad-hoc substitution door is
the only one that needs `wrap` around the command**, so `wrap` is the
optional second layer, not the main guard. For interactive use it can be
made transparent with a shell alias/PATH shim that routes `nix` through
`machokeeper wrap -- nix`. That shim has one honest limit: it only sees
invocations that go through it — a script hard-coding
`/run/current-system/sw/bin/nix` bypasses the alias. That bypass is
exactly why the module (hook + activation scan), which nothing in a
generation can dodge, is primary and `wrap` is secondary.

## Relationship to the in-daemon patch

machokeeper is the deliberate salvage of the in-daemon C++ repair after
[NixOS/nix#15638](https://github.com/NixOS/nix/pull/15638) was declined
upstream (keep Mach-O format knowledge out of libstore). It carries the
same validated repair math, out of tree by design — no daemon fork, no
`trusted-users`, no signing keys.

The out-of-band doors cover the same entry points as the in-daemon
patch, and differ on exactly **one axis: pre-registration vs pre-use.**

- The in-daemon patch repairs bytes *before they are registered* as a
  valid store path — broken bytes never enter the store, so there is
  nothing to race.
- machokeeper repairs *before first use*: the activation scan repairs a
  generation's paths after substitution but before the generation goes
  live, and the post-build hook repairs an output before it is used. For
  the reported pain — a broken login shell, a broken build input at the
  next rebuild — pre-use is **nearly equivalent** to pre-registration.
- The residual difference is the ad-hoc substitution door: an ad-hoc
  `nix run` of a freshly-substituted darwin binary executed immediately,
  outside `wrap`, is the one case the inline patch catches that
  machokeeper does not unless the command was wrapped.

## No standing daemon

There is deliberately **no long-lived machokeeper process** — no
privileged `launchd` daemon, no `systemd` service, no periodic timer, no
FSEvents store-watcher. The module wires only `activationScripts` (which
run during a switch and exit) and the post-build hook (a short-lived
child per build). Both a maintenance timer and a store-watcher were
considered and cut. The reasons:

- **It adds no coverage.** A steady-state store is empty of new breakage
  between generations — every door that lets stale bytes in is already
  guarded at the moment they enter. A patrol would run forever and find
  nothing.
- **It is the wrong security posture.** machokeeper parses
  attacker-influenceable bytes only in short-lived, unprivileged
  children, and mutates the store only on explicit consent (`--fix`,
  enabling the module, a switch). A standing root daemon watching the
  store and auto-repairing would be a long-lived privileged process
  *continuously* parsing untrusted bytes — exactly the surface the
  [threat model](../THREAT-MODEL.md) is built to avoid.
- **It is standing state.** "No daemons, no timers, no state": the only
  state is a first-enable marker file and the undo journals.

What replaces a patrol: the one-shot first-enable sweep (repair what is
already broken, once), and `doctor` on demand.

## Store-write safety (GC and optimise)

The in-daemon patch repairs a path *before it is registered valid*,
inside `addToStore` under a temp root and a per-path lock, and before
`optimisePath`. GC and `optimiseStore` only ever touch already-valid
paths, so that ordering makes the repair race-free by construction — no
explicit lock is needed.

machokeeper repairs *after* the path is valid (and possibly already
hardlinked by `auto-optimise-store`), so it cannot rely on that
ordering. It defends the store-write path three ways:

- **Atomic, hardlink-safe writes.** Every repaired file is written to a
  sibling temp and `rename`d over the original — atomic on a
  same-filesystem rename, and a *fresh inode*, so a hardlink shared by
  `auto-optimise-store` is never written through. This is the same
  atomic rename optimise itself uses.
- **GC coordination.** During a store-path repair, machokeeper holds
  nix's GC lock (`/nix/var/nix/gc.lock`) in **shared** mode — the same
  `flock(LOCK_SH)` the daemon takes for its own store writes (GC takes
  it `LOCK_EX`). So a concurrent `nix-store --gc` cannot collect a path
  mid-repair. Best-effort: if the lock can't be taken, the repair still
  proceeds (the other two defenses hold).
- **Detectable, self-healing.** After repair the recorded NAR hash is
  reconciled to the repaired bytes, so any regression is caught by
  `nix-store --verify --check-contents` and fixed by a re-run.

The shared GC lock deliberately does **not** exclude a concurrent
`nix-store --optimise` (which also takes it shared). That leaves one
narrow race: an optimise that reads a file's pre-repair bytes and then
renames a hardlink-to-stale-canonical over it *after* the repair, in the
few milliseconds between machokeeper's read and its rename. Excluding it
would require taking the GC lock *exclusive* — making `doctor --fix`
behave like GC and stall the whole daemon for the scan. The race is not
worth that cost: it needs a manual `--optimise` running concurrently
with `--fix`, and its result (bytes regressed, DB hash still repaired)
is caught by `nix-store --verify` and undone by a re-run — never silent
corruption.

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
