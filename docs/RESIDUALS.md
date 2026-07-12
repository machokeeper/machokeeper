# Accepted-residual register

Consciously accepted tradeoffs — verified and argued once so reviews stop
re-flagging them. Cite entries by ID in review output ("accepted per R-003").

Rules:

- **Adding**: a review that ACCEPTS a new residual adds the entry in the same
  PR (id, one-line risk, why accepted, where argued). Without the entry, the
  next review re-litigates it.
- **Pruning**: each entry names the code/behavior it describes; if that is
  gone or the tradeoff is fixed, delete the entry in the fixing PR.
- **Challenging**: entries are decisions, not laws. To overturn one, argue it
  in the PR that changes the behavior — not by re-flagging it in review.

The security-relevant residuals (R-001–R-004) are narrated in
[THREAT-MODEL.md](../THREAT-MODEL.md) § "Residual risks"; this table is the
cite-by-ID index and the home for correctness residuals going forward.

| ID | Residual | Why accepted | Argued at |
|---|---|---|---|
| R-001 | A repaired path diverges from the substituter's copy — `nix store verify` reports a hash mismatch, and `nix store verify --repair` would restore the *broken* cached copy | Repair is out-of-band by design (see DESIGN.md "doors"); the byte-exact undo journal is the record of what was repaired. The stale-signature breakage is the upstream problem machokeeper exists to work around | THREAT-MODEL.md |
| R-002 | `--fix-live` reconciles the Nix DB while the daemon may be running; a concurrent operation on the same path during the reconcile window is not excluded by machokeeper | The register-validity call is a normal daemon operation; the window is narrow. `--fix` (unrooted paths only) avoids it — prefer it when the path can be unrooted | THREAT-MODEL.md |
| R-003 | `wrap`'s substitution-log parsing is heuristic (nix `internal-json` is not a stable interface) | Treated as best-effort: pre-fetch list is advisory, with a repair-and-retry-once fallback. A missed path degrades to exactly the failure the user would have had without `wrap` — never a wrong repair | THREAT-MODEL.md |
| R-004 | Single-user (non-daemon) installs run the Mach-O parser at the invoking user's privilege — root, for a root-owned store | Matches every other tool on such installs; the engine's fuzzing + bounds discipline (never OOB/panic on hostile bytes) is the mitigation, not a privilege boundary machokeeper can add | THREAT-MODEL.md |

Not residuals (never report, no ID): anything `nix fmt` / `go vet` /
`golangci-lint` already gates — CI enforces it.
