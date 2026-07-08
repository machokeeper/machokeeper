# Eval check for the darwin activation scan/sweep wiring. Unlike NixOS,
# nix-darwin has no generic activation-script dag: its `activate` splices
# only a fixed, enumerated set of script names (preActivation … homebrew,
# postActivation), so a custom `system.activationScripts.<name>` evaluates
# fine but is silently never run. This regression-guards that the module's
# scan-generation + first-enable sweep actually land in the assembled
# activate script (`system.activationScripts.script.text`), with the user
# changing nothing but `enable`. Darwin-only (darwinSystem).
{
  pkgs,
  self,
  nix-darwin,
  system,
}:
let
  sys = nix-darwin.lib.darwinSystem {
    inherit system;
    modules = [
      self.darwinModules.default
      {
        nixpkgs.hostPlatform = system;
        system.stateVersion = 6;
      }
      { services.machokeeper.enable = true; } # …and just enables machokeeper
    ];
  };
  # The fully-assembled activate body nix-darwin runs (the concatenation of
  # every spliced activationScripts.*.text). If the module put its snippet
  # under a name `activate` doesn't reference, it won't appear here.
  activate = pkgs.writeText "darwin-activate" sys.config.system.activationScripts.script.text;
in
pkgs.runCommand "machokeeper-module-darwin-activation" { } ''
  echo "the activation scan must be spliced into nix-darwin's activate script…"
  grep -q 'scan-generation' ${activate} || {
    echo "FAIL: scan-generation missing — a custom activationScripts.<name> is silently dropped by nix-darwin; use a spliced slot (postActivation)"
    exit 1
  }
  echo "…and so must the one-time first-enable full-store sweep."
  grep -q 'first-enable full-store sweep' ${activate} || {
    echo "FAIL: first-enable sweep missing from the darwin activate script"
    exit 1
  }
  touch $out
''
