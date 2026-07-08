# Eval check for the post-build-hook auto-chaining: a NixOS system that
# enables machokeeper *and* keeps a prior nix.settings.post-build-hook
# must produce a nix.conf where machokeeper's dispatcher wins the single
# hook slot and chains the prior hook — with the user changing nothing
# but `enable`. Linux-only (nixosSystem); built natively in CI.
{
  pkgs,
  self,
  nixpkgs,
}:
let
  sys = nixpkgs.lib.nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      self.nixosModules.default
      {
        boot.loader.grub.enable = false;
        fileSystems."/" = {
          device = "x";
          fsType = "ext4";
        };
        system.stateVersion = "24.05";
      }
      { nix.settings.post-build-hook = "/USER-CACHE-HOOK"; } # user keeps their hook
      { services.machokeeper.enable = true; } # …and just enables machokeeper
    ];
  };
  conf = sys.config.environment.etc."nix/nix.conf".source;
in
pkgs.runCommand "machokeeper-module-autochain" { } ''
  echo "the user's prior hook line is present…"
  grep -q 'post-build-hook = /USER-CACHE-HOOK' ${conf} || { echo "FAIL: user hook line missing"; exit 1; }
  echo "…and machokeeper appended its dispatcher after it (wins the slot)…"
  disp=$(grep -oE '/nix/store/[a-z0-9]+-machokeeper-post-build-hook' ${conf} | tail -1)
  [ -n "$disp" ] || { echo "FAIL: no machokeeper dispatcher in nix.conf"; exit 1; }
  echo "…which runs machokeeper and then chains the prior hook."
  grep -q 'machokeeper post-build-hook' "$disp" || { echo "FAIL: dispatcher does not run machokeeper"; exit 1; }
  grep -q '/USER-CACHE-HOOK' "$disp" || { echo "FAIL: dispatcher does not chain the prior hook"; exit 1; }
  touch $out
''
