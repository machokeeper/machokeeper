# Shared machokeeper module logic for nix-darwin, NixOS, and
# home-manager. `platform` selects the small differences (how the
# activation script and the nix.conf hook are wired on each).
{
  config,
  lib,
  pkgs,
  self,
  platform, # "darwin" | "nixos" | "home"
  ...
}:
let
  cfg = config.services.machokeeper;
  system = pkgs.stdenv.hostPlatform.system;
  machokeeper = cfg.package;
  bin = lib.getExe machokeeper;

  # The post-build hook must chain any hook the user already set, since
  # nix.conf's post-build-hook is single-valued. We generate a wrapper
  # script that runs machokeeper's hook and then execs the prior one.
  chainedHook = pkgs.writeShellScript "machokeeper-post-build-hook" ''
    ${bin} post-build-hook || true
    ${lib.optionalString (cfg.chainPostBuildHook != null) ''
      exec ${cfg.chainPostBuildHook} "$@"
    ''}
  '';
in
{
  options.services.machokeeper = {
    enable = lib.mkEnableOption "machokeeper: keep the Nix store's Mach-O signatures valid";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${system}.default;
      defaultText = lib.literalExpression "machokeeper.packages.\${system}.default";
      description = "The machokeeper package to use.";
    };

    postBuildHook = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Wire machokeeper as the nix `post-build-hook`, so locally built
        outputs are repaired before first use. Chains any existing hook
        via {option}`services.machokeeper.chainPostBuildHook`.
      '';
    };

    chainPostBuildHook = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        An existing post-build-hook program to run after machokeeper's.
        Set this to your prior `nix.settings.post-build-hook` (e.g. a
        cachix or binary-cache push hook), since nix allows only one.
      '';
    };

    scanOnActivation = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Scan the incoming generation's new store paths during
        activation (after substitution, before the generation goes
        live) and act per {option}`onActivation`. Not available on
        home-manager (no privileged activation); use the hook + doctor
        there.
      '';
    };

    onActivation = lib.mkOption {
      type = lib.types.enum [
        "repair"
        "refuse"
      ];
      default = "repair";
      description = ''
        What the activation scan does with a broken signature:
        `repair` fixes it in place before the generation goes live;
        `refuse` fails the switch so nothing broken is activated.
      '';
    };

    sweepOnFirstEnable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        The first time machokeeper activates, sweep the whole store
        once to repair anything already broken. Subsequent activations
        only scan the generation delta. A marker file records that the
        sweep has run.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    let
      marker = "/nix/var/machokeeper/.swept";
      activation = ''
        ${lib.optionalString cfg.sweepOnFirstEnable ''
          if [ ! -e ${marker} ]; then
            echo "machokeeper: first-enable full-store sweep (one time)..."
            ${bin} sweep || true
            mkdir -p /nix/var/machokeeper && : > ${marker}
          fi
        ''}
        ${lib.optionalString cfg.scanOnActivation ''
          machokeeper_new="$systemConfig"
          machokeeper_old="$(readlink -f /run/current-system 2>/dev/null || true)"
          ${bin} scan-generation ${lib.optionalString (cfg.onActivation == "refuse") "--refuse"} \
            "''${machokeeper_new:-}" "''${machokeeper_old:-}" || \
            ${if cfg.onActivation == "refuse" then "exit 1" else "true"}
        ''}
      '';
    in
    lib.mkMerge [
      (lib.mkIf cfg.postBuildHook {
        nix.settings.post-build-hook = "${chainedHook}";
      })

      (lib.mkIf (platform == "darwin" && cfg.scanOnActivation) {
        system.activationScripts.machokeeper.text = ''
          systemConfig="$systemConfig"
          ${activation}
        '';
      })

      (lib.mkIf (platform == "nixos" && cfg.scanOnActivation) {
        system.activationScripts.machokeeper = ''
          systemConfig="''${systemConfig:-$(readlink -f /run/current-system)}"
          ${activation}
        '';
      })
    ]
  );
}
