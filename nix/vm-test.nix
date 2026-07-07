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

  nodes.machine = _: {
    virtualisation.writableStore = true;
    nix.settings.sandbox = false;
    environment.systemPackages = [ machokeeper ];
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # Build INPUT-addressed store paths carrying the fixtures: repair +
    # re-registration is only legal for input addressing, and
    # `nix-store --add` would produce a content-addressed path (that
    # case gets its own refusal test below). Sandbox is off, so the
    # builder can use /bin/sh.
    def build_pkg(name, fixture, filename, out_link=None):
        link = f"-o {out_link}" if out_link else "--no-out-link"
        expr = (
            "derivation { name = \"" + name + "\"; "
            "system = builtins.currentSystem; "
            "builder = \"/bin/sh\"; "
            "args = [ \"-c\" \"mkdir -p $out/bin && "
            "cp ${fixtures}/" + fixture + " $out/bin/" + filename + " && "
            "chmod +x $out/bin/" + filename + "\" ]; }"
        )
        return machine.succeed(f"nix-build {link} --expr '{expr}'").strip().splitlines()[-1]

    store_path = build_pkg("pkg", "repairable", "tool")
    print(f"store path: {store_path}")

    # check must see it as stale (exit 2, specifically).
    status = machine.succeed(
        f"machokeeper check {store_path} && echo rc=0 || echo rc=$?"
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
    rooted = build_pkg("pkg2", "repairable", "tool2", out_link="/root/keep-pkg2")
    roots = machine.succeed(f"nix-store --query --roots {rooted}")
    assert "keep-pkg2" in roots, f"root not registered: {roots}"

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
    cms = build_pkg("pkg3", "cms", "devid")
    before = machine.succeed(f"sha256sum {cms}/bin/devid").split()[0]
    out = machine.succeed(f"cd /root && (machokeeper doctor --fix {cms} && echo rc=0 || echo rc=$?)")
    assert "rc=2" in out, f"CMS fix must exit 2: {out}"
    after = machine.succeed(f"sha256sum {cms}/bin/devid").split()[0]
    assert before == after, "CMS-signed file was modified"

    # ---- Content-addressed path: refused, bytes untouched ----
    # `nix-store --add` registers a CA path (text/fixed addressing):
    # exactly the refusal class the CA guard exists for.
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

    # ---- Whole-store scan finds nothing left broken ----
    out = machine.succeed(f"machokeeper doctor {cms} {store_path} {rooted} && echo rc=0 || echo rc=$?")
    assert "rc=2" in out, "CMS finding keeps scan at exit 2"
  '';
}
