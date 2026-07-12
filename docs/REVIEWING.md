# Reviewing changes in machokeeper

Repo-specific review guidance. Read this before reviewing a diff here.
[AGENTS.md](../AGENTS.md), [CONTRIBUTING.md](../CONTRIBUTING.md), and
[docs/DESIGN.md](DESIGN.md) are authoritative over this file; this file
calibrates severity and points at what generic review instincts miss.

## What this is, in one review-relevant sentence

A tool that writes to the Nix store as root to repair stale Mach-O page-hash
signatures — so correctness means it rewrites **only** the stale hash slots,
**always** with a byte-exact undo journal and a re-verify, and **never**
touches a signature class or path it doesn't own; a false repair corrupts a
binary the OS trusts.

## Severity calibration (what P0–P3 mean here)

Reserve **P0** for anything that breaks a repair-scope invariant
(CONTRIBUTING § "Invariants that are not up for negotiation"):

- Repairing a byte that is **not** a stale hash slot.
- A repair path with **no journaled undo**, or that **isn't re-verified**
  before it counts.
- Modifying a **CMS / Developer-ID**-signed file or a **content-addressed**
  path — ever.
- Waving through an **unknown/unparseable** signature class instead of
  treating it as broken (the detection bias is load-bearing).
- **Weakening the verification triad** (see below) — narrowing a fuzz
  property, editing the oracle to match the engine, deleting a byte-fixture.
- The parser doing **I/O**, or running with **privilege it doesn't need**.

**P1**: a store mutation with no daemon-free test; a detection **false
negative** (stale bytes waved through) or a repair that changes NAR length /
skips the NAR-hash reconciliation; a GC-/optimise-unsafe store write; a `wrap`
path that could run a not-yet-repaired binary.

**P2**: good-citizen / throttling regressions (priority, `--jobs`, page-cache
eviction); heuristic-parse handling that fails unsafe rather than degrading to
the pre-existing failure; error messages that don't name the file + slot + what
disagreed.

**P3 / nit**: style. Anything `nix fmt` / `go vet` / `golangci-lint` enforces
is **not** a finding at any severity — the gate catches it.

## The correctness gate is the verification triad (do not weaken)

Engine changes are gated by the triad in [AGENTS.md](../AGENTS.md), and it is
the primary review lens: byte-fixture unit tests, the **independent** Python
oracle (`internal/oracle/stale.py` — shares no code with the engine on
purpose), and the fuzz targets. **A new engine test must fail on the pre-fix
code — show red before green.** If engine and oracle disagree, one has a bug;
say which you believe and why — never reconcile them by editing the oracle.

## Danger zones (small diffs, big blast radius)

| Path | Why |
|---|---|
| `engine/engine.go` + its three test files | The repair/verify math; a wrong slot = a corrupted trusted binary |
| `internal/oracle/stale.py` | The independent cross-check; a change that makes it agree with the engine destroys the triad |
| `engine/fuzz_test.go` | The never-panic/OOB, check-never-mutates, repair-preserves-length properties |
| `internal/doctor` (store write, `gclock`) | Where repairs hit the real store; GC-lock coordination + `--fix` vs `--fix-live` scope |
| `internal/nixstore` | NAR-hash reconciliation after repair; a drift silently poisons the DB |
| `internal/wrap` | Heuristic `internal-json` parse; must degrade to the pre-existing failure, never a wrong repair |
| `nix/module-common.nix`, `internal/hook` | Post-build / activation entry points that write the store as root |

## Do not report (accepted residuals)

See [RESIDUALS.md](RESIDUALS.md); cite by ID ("accepted per R-002"). Never
report anything the format/vet/lint gate enforces.

## Review feedback contract

End a review over this repo with a short block:

- **Checked**: which invariants / danger zones applied and whether any fired.
- **Uncovered**: a confirmed finding no invariant covers — propose the rule.
- **Register hits**: a near-flag suppressed by a RESIDUALS.md entry (cite the
  ID) — evidence the register earns its keep.

## Verification recipes (run these; don't reason from the diff alone)

Pre-merge gate (from AGENTS.md): `nix fmt` clean + `go vet` + `go test -race
./...` + `golangci-lint run`, plus `nix flake check && nix build .#default`
when nix files change. All fresh, exit 0, this session — paste output, don't
recall it. Real-binary CI fixtures are human-owned: if one fails, explain the
behavior change and stop.
