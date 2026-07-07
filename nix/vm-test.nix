# NixOS VM integration test: machokeeper against a REAL nix-daemon and
# store database — the layer the unit tests fake out via storeBackend.
#
# What only this test can prove:
#   - doctor --fix reconciling an unrooted store path's recorded NAR
#     hash in place (--register-validity --reregister --hash-given) so
#     `nix-store --verify --check-contents` accepts the repaired bytes.
#   - --fix refusing a GC-rooted path via real --query --roots output,
#     and --fix-live reconciling it.
#   - CMS refusal, content-addressed refusal, and the undo journal
#     round-trip through the real CLI on files inside /nix/store.
#
# The broken binaries are built on the HOST as ordinary derivations
# (input-addressed, so their recorded hash is a real hash of the broken
# bytes) and copied into the VM via additionalPaths — no in-VM building,
# no network, no OOM. Mach-O is just bytes, so no macOS host is needed
# and nothing from the store is executed.
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

  # A broken package as a host-built store path: input-addressed, so the
  # daemon records a real NAR hash of the broken bytes. Distinct names
  # give distinct paths (identical bytes would collide).
  brokenPkg =
    name: fixture: file:
    pkgs.runCommand name { } ''
      mkdir -p $out/bin
      cp ${fixtures}/${fixture} $out/bin/${file}
      chmod +x $out/bin/${file}
    '';
  pkgUnrooted = brokenPkg "mk-unrooted" "repairable" "tool";
  pkgRooted = brokenPkg "mk-rooted" "repairable" "tool2";
  pkgCms = brokenPkg "mk-cms" "cms" "devid";
in
pkgs.testers.runNixOSTest {
  name = "machokeeper-nixstore";

  nodes.machine = _: {
    # doctor writes repaired bytes into store files directly (its real
    # deployment is root on darwin, no read-only bind mount); NixOS
    # mounts /nix/store read-only, so lift that for the test.
    virtualisation.writableStore = true;
    boot.nixStoreMountOpts = [ "rw" ];
    # Enough RAM for nix-store --verify --check-contents over the store.
    virtualisation.memorySize = 3072;
    # The broken fixtures, registered as valid paths in the VM's store.
    virtualisation.additionalPaths = [
      pkgUnrooted
      pkgRooted
      pkgCms
    ];
    environment.systemPackages = [ machokeeper ];
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    store_path = "${pkgUnrooted}"
    rooted = "${pkgRooted}"
    cms = "${pkgCms}"

    # check must see the unrooted path as stale (exit 2, specifically).
    status = machine.succeed(f"machokeeper check {store_path} && echo rc=0 || echo rc=$?")
    assert "rc=2" in status, f"check exit code: {status}"

    # ---- Unrooted repair: in-place hash reconciliation ----
    machine.succeed(f"cd /root && machokeeper doctor --fix {store_path}")
    machine.succeed(f"machokeeper check {store_path}")
    # The recorded NAR hash must match the repaired bytes: a full content
    # verification over the store must not complain about this path.
    machine.succeed("nix-store --verify --check-contents 2>&1 | tee /dev/stderr | (! grep -i 'differs\\|corrupt')")

    # The undo journal exists and undo restores the broken bytes.
    # (find over existing dirs, so the pipe doesn't trip pipefail the
    # way a non-matching `ls` glob would.)
    journal = machine.succeed(
        "find /root /nix/var/machokeeper -name 'machokeeper-undo-*.json' 2>/dev/null | head -1"
    ).strip()
    assert journal, "no undo journal written"
    machine.succeed(f"machokeeper undo {journal}")
    machine.fail(f"machokeeper check {store_path}")
    # Re-repair so the store is coherent again for the whole-store checks.
    machine.succeed(f"cd /root && machokeeper doctor --fix {store_path}")

    # ---- Rooted path: --fix must refuse, --fix-live must reconcile ----
    machine.succeed(f"ln -sfn {rooted} /nix/var/nix/gcroots/keep-rooted")
    roots = machine.succeed(f"nix-store --query --roots {rooted}")
    assert "keep-rooted" in roots, f"root not registered: {roots}"

    # Plain --fix: refused (exit 2), bytes untouched.
    out = machine.succeed(f"cd /root && (machokeeper doctor --fix {rooted} && echo rc=0 || echo rc=$?)")
    assert "rc=2" in out, f"rooted --fix should refuse: {out}"
    assert "SKIP" in out, f"expected SKIP notice: {out}"
    machine.fail(f"machokeeper check {rooted}")

    # --fix-live: repaired in place, hash row reconciled.
    machine.succeed(f"cd /root && machokeeper doctor --fix-live {rooted}")
    machine.succeed(f"machokeeper check {rooted}")
    machine.succeed("nix-store --verify --check-contents 2>&1 | tee /dev/stderr | (! grep -i 'differs\\|corrupt')")

    # ---- CMS: never touched, even with --fix ----
    before = machine.succeed(f"sha256sum {cms}/bin/devid").split()[0]
    out = machine.succeed(f"cd /root && (machokeeper doctor --fix {cms} && echo rc=0 || echo rc=$?)")
    assert "rc=2" in out, f"CMS fix must exit 2: {out}"
    after = machine.succeed(f"sha256sum {cms}/bin/devid").split()[0]
    assert before == after, "CMS-signed file was modified"

    # ---- Content-addressed path: refused, bytes untouched ----
    # `nix-store --add` registers a CA path (text/fixed addressing) — no
    # build, so it is cheap — exactly the refusal class the guard exists
    # for.
    machine.succeed(
        "mkdir -p /root/capkg/bin",
        "cp ${fixtures}/repairable /root/capkg/bin/catool",
        "chmod +x /root/capkg/bin/catool",
    )
    ca_path = machine.succeed("nix-store --add /root/capkg").strip()
    out = machine.succeed(f"cd /root && (machokeeper doctor --fix {ca_path} && echo rc=0 || echo rc=$?)")
    assert "rc=2" in out, f"CA fix must exit 2: {out}"
    assert "content-addressed" in out, f"expected CA skip notice: {out}"
    machine.fail(f"machokeeper check {ca_path}")  # still broken, untouched

    # ---- Whole-store scan still flags the CMS path (exit 2) ----
    out = machine.succeed(f"machokeeper doctor {cms} {store_path} {rooted} && echo rc=0 || echo rc=$?")
    assert "rc=2" in out, "CMS finding keeps scan at exit 2"
  '';
}
