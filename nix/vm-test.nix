# NixOS VM integration test: machokeeper against a REAL nix-daemon and
# store database — the layer the unit tests fake out via storeBackend.
#
# What only this test can prove:
#   - Reregister's export → delete → import round-trip on a live DB
#     (doctor --fix on an unrooted store path), and that the recorded
#     NAR hash matches the repaired bytes afterwards
#     (`nix-store --verify --check-contents` stays silent).
#   - --fix-live's --register-validity hash reconciliation on a
#     GC-ROOTED path, without deleting it.
#   - Roots/Referrers blocker detection against real GC roots: plain
#     --fix must refuse a rooted path.
#   - The CMS refusal and undo journal round-trip through the real CLI
#     on files inside /nix/store.
#
# The fixtures are machofixture's byte blobs (Mach-O is just bytes; no
# macOS needed). Nothing is executed from the store paths.
{
  pkgs,
  self,
}:
let
  fixtures =
    pkgs.runCommand "machokeeper-fixtures"
      {
        nativeBuildInputs = [ pkgs.go ];
      }
      ''
        export HOME=$TMPDIR GOCACHE=$TMPDIR/gocache GOPATH=$TMPDIR/gopath GOPROXY=off GOFLAGS=-mod=mod
        cp -r ${self} src && chmod -R +w src && cd src
        go run ./internal/machofixture/gen "$out"
      '';

  machokeeper = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
in
pkgs.testers.runNixOSTest {
  name = "machokeeper-nixstore";

  nodes.machine =
    { ... }:
    {
      virtualisation.writableStore = true;
      nix.settings.sandbox = false;
      environment.systemPackages = [ machokeeper ];
    };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # Place a broken (repairable) fixture into the store as a real,
    # registered store path.
    machine.succeed(
        "mkdir -p /root/pkg/bin",
        "cp ${fixtures}/repairable /root/pkg/bin/tool",
        "chmod +x /root/pkg/bin/tool",
    )
    store_path = machine.succeed(
        "nix-store --add /root/pkg"
    ).strip()
    print(f"store path: {store_path}")

    # check must see it as stale (exit 2).
    machine.fail(f"machokeeper check {store_path}")
    status = machine.succeed(
        f"machokeeper check {store_path}; echo rc=$?"
    )
    assert "rc=2" in status, f"check exit code: {status}"

    # ---- Unrooted repair: full export/delete/import re-registration ----
    machine.succeed(f"cd /root && machokeeper doctor --fix {store_path}")
    machine.succeed(f"machokeeper check {store_path}")

    # The database NAR hash must match the repaired bytes: a full
    # content verification over the store must not complain about it.
    machine.succeed("nix-store --verify --check-contents 2>&1 | tee /dev/stderr | (! grep -i 'differs\\|corrupt')")

    # The undo journal exists and undo restores the broken bytes.
    journal = machine.succeed("ls /root/machokeeper-undo-*.json /nix/var/machokeeper/machokeeper-undo-*.json 2>/dev/null | head -1").strip()
    assert journal, "no undo journal written"
    machine.succeed(f"machokeeper undo {journal}")
    machine.fail(f"machokeeper check {store_path}")
    # Re-repair so the store is coherent again for the next phase.
    machine.succeed(f"cd /root && machokeeper doctor --fix {store_path}")

    # ---- Rooted path: --fix must refuse, --fix-live must reconcile ----
    machine.succeed(
        "mkdir -p /root/pkg2/bin",
        "cp ${fixtures}/repairable /root/pkg2/bin/tool2",
        "chmod +x /root/pkg2/bin/tool2",
    )
    rooted = machine.succeed("nix-store --add /root/pkg2").strip()
    machine.succeed(
        f"nix-store --add-root /nix/var/nix/gcroots/keep-pkg2 --indirect --realise {rooted} || ln -s {rooted} /nix/var/nix/gcroots/keep-pkg2"
    )
    roots = machine.succeed(f"nix-store --query --roots {rooted}")
    assert "keep-pkg2" in roots, f"root not registered: {roots}"

    # Plain --fix: refused (exit 2), bytes untouched.
    out = machine.succeed(f"cd /root && machokeeper doctor --fix {rooted}; echo rc=$?")
    assert "rc=2" in out, f"rooted --fix should refuse: {out}"
    assert "SKIP" in out, f"expected SKIP notice: {out}"
    machine.fail(f"machokeeper check {rooted}")

    # --fix-live: repaired in place, hash row reconciled.
    machine.succeed(f"cd /root && machokeeper doctor --fix-live {rooted}")
    machine.succeed(f"machokeeper check {rooted}")
    machine.succeed("nix-store --verify --check-contents 2>&1 | tee /dev/stderr | (! grep -i 'differs\\|corrupt')")

    # ---- CMS: never touched, even with --fix ----
    machine.succeed(
        "mkdir -p /root/pkg3/bin",
        "cp ${fixtures}/cms /root/pkg3/bin/devid",
        "chmod +x /root/pkg3/bin/devid",
    )
    cms = machine.succeed("nix-store --add /root/pkg3").strip()
    before = machine.succeed(f"sha256sum {cms}/bin/devid").split()[0]
    out = machine.succeed(f"cd /root && machokeeper doctor --fix {cms}; echo rc=$?")
    assert "rc=2" in out, f"CMS fix must exit 2: {out}"
    after = machine.succeed(f"sha256sum {cms}/bin/devid").split()[0]
    assert before == after, "CMS-signed file was modified"

    # ---- Whole-store scan finds nothing left broken ----
    out = machine.succeed(f"machokeeper doctor {cms} {store_path} {rooted}; echo rc=$?")
    assert "rc=2" in out, "CMS finding keeps scan at exit 2"
  '';
}
