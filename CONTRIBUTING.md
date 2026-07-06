# Contributing

Thanks for helping keep Nix stores' Mach-O signatures valid.

## Development

```console
nix develop        # or: go 1.23+
go test ./...      # unit + oracle cross-validation
go test -race ./...
nix flake check    # package + module eval
```

Lint locally with `golangci-lint run` (config in `.golangci.yml`).

## What to know before changing the engine

`engine/` is the repair math and is validated three ways that must all
stay green:

1. Hand-built byte-fixture unit tests (`engine/engine_test.go`).
2. An independent Python page-hash verifier (`internal/oracle/stale.py`)
   that shares no code with the engine (`engine/oracle_test.go`).
3. Native fuzz targets (`engine/fuzz_test.go`): detection and check must
   never panic or read out of bounds, check must never mutate, repair
   must preserve length.

If you change how hashes are computed, all three must agree, and the
[real-binary CI](.github/workflows/ci.yml) (broken cache.nixos.org
binaries) must still pass.

## Invariants that are not up for negotiation

- The parser does no I/O and never runs with privilege it doesn't need.
- Repair changes only stale hash slots; every write is journaled for
  byte-exact undo; a repair is re-verified before it counts.
- Store metadata changes go only through documented `nix-store`
  plumbing.
- Developer-ID (CMS) and content-addressed paths are never modified.

See [THREAT-MODEL.md](THREAT-MODEL.md).

## Commits and PRs

Describe the code, not the process. Keep each PR to one concern. New
behaviour needs a test; new store-touching behaviour needs one that runs
without a live daemon (inject the store backend, as the doctor tests do).
