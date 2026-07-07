# AGENTS.md

machokeeper detects and repairs stale Mach-O page-hash signatures in Nix
stores. `engine/` is the repair math; everything else is plumbing around it.
Read [CONTRIBUTING.md](CONTRIBUTING.md) (invariants, engine change rules) and
[THREAT-MODEL.md](THREAT-MODEL.md) before touching `engine/` or anything that
writes to a store.

## Commands

| Command | What / cost |
|---|---|
| `go build ./...` | fast; run after every edit |
| `go test ./...` | unit + oracle cross-validation; ~seconds. **The oracle test skips silently without `python3` on PATH** — run inside `nix develop` or a green run proves less than it looks |
| `go test -race ./...` | the authoritative test gate; slower, run before claiming done |
| `nix fmt` | treefmt over the whole tree (gofmt, nixfmt, ruff, shfmt, yamlfmt); CI rejects unformatted code |
| `go vet ./...` | part of CI |
| `golangci-lint run` | lint gate (config `.golangci.yml`); in `nix develop` |
| `nix flake check && nix build .#default` | package + module eval; run when touching `flake.nix`, `nix/`, or module hooks |
| `go test -fuzz=FuzzDetect -fuzztime=30s ./engine/` | bounded fuzz spot-check (also FuzzCheck, FuzzRepair); CI runs these bounded |

Pre-merge = `nix fmt` clean + `go vet` + `go test -race ./...` +
`golangci-lint run`, plus the nix pair when nix files changed. All fresh,
exit 0, this session — paste output, don't recall it.

## The verification triad (do not weaken)

Engine changes must keep all three green, and they must keep *disagreeing
independently* — that's the design:

1. Byte-fixture unit tests (`engine/engine_test.go`, fixtures built by
   `internal/machofixture`).
2. The independent Python oracle (`internal/oracle/stale.py`) — shares no
   code with the engine on purpose. **Never modify the oracle to make the
   engine pass.** If engine and oracle disagree, one of them has a bug;
   stop and say which one you believe and why.
3. Fuzz targets (`engine/fuzz_test.go`) — never panic/OOB on detection and
   check, check never mutates, repair preserves length. Never delete or
   narrow a fuzz property to get green.

A new engine test must fail on the pre-fix code — show red before green.
Real-binary CI fixtures (broken cache.nixos.org binaries) are human-owned:
if one fails, explain the behavior change and stop.

## Hard rules for agents

- **Never run `doctor --fix`, `--fix-live`, or anything with `sudo` against
  a real store path on this machine.** Test store mutation by injecting the
  store backend, as `internal/doctor` tests do (CONTRIBUTING has the rule:
  store-touching behavior needs a test that runs without a live daemon).
- Repair-scope invariants (only stale hash slots; journaled undo; re-verify
  after repair; never CMS/Developer-ID; never CA paths) are non-negotiable —
  CONTRIBUTING lists them. A PR relaxing one is wrong by definition.
- `gosec` suppressions: the blanket G204/G304/G115 rationale in
  `.golangci.yml` covers *existing* patterns. New suppressions need a
  one-line reason at the site; never widen the global excludes.
- Unknown/unparseable signature classes are treated as broken, never waved
  through. Preserve that bias when extending detection.
- Don't push, don't tag releases; release.yml signs artifacts — human act.

## Where to look

| Task | Where |
|---|---|
| Repair/verify math | `engine/engine.go` (+ its three test files) |
| CLI + doctor flow | `cmd/machokeeper`, `internal/doctor` |
| Store registration / NAR hash | `internal/nixstore` |
| Post-build & activation hooks | `internal/hook`, `internal/wrap`, `nix/module-common.nix` |
| Test fixture construction | `internal/machofixture` |
| Real-binary validation | `scripts/validate-real-binaries.py`, CI `real-binaries-*` jobs |
| Why signatures break at all | README intro + NixOS/nixpkgs#507531, NixOS/nix#6065 |

## Conventions

Commits describe the code as it stands, not the process. One concern per
PR; new behavior needs a test. Match the existing error-message style:
errors name the file, the slot, and what disagreed.
