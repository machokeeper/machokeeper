# Shared machokeeper module logic for nix-darwin, NixOS, and
# home-manager. `platform` selects the small differences (how the
# activation script is wired, and that home-manager cannot repair the
# store as an unprivileged user).
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

  # nix.conf's post-build-hook is single-valued, so machokeeper must
  # chain any hook already configured rather than clobber it. Reading
  # the *merged* `nix.settings.post-build-hook` (the user's value, from
  # any module, however set) and writing our dispatcher via
  # `nix.extraOptions` — which nix appends after `settings`, so the last
  # definition wins — chains it with no eval cycle and no need for the
  # user to move their hook. `extraPostBuildHooks` adds any further
  # hooks not expressed through nix.settings.
  priorHook = config.nix.settings.post-build-hook or null;
  chained =
    lib.optional (priorHook != null && priorHook != "") (toString priorHook)
    ++ lib.optional (cfg.chainPostBuildHook != null) (toString cfg.chainPostBuildHook)
    ++ map toString cfg.extraPostBuildHooks;

  dispatcher = pkgs.writeShellScript "machokeeper-post-build-hook" ''
    ${bin} post-build-hook || true
    ${lib.concatMapStringsSep "\n" (h: "${h} \"$@\" || true") chained}
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
      default = platform != "home";
      defaultText = lib.literalExpression ''platform != "home"'';
      description = ''
        Wire machokeeper as the nix `post-build-hook`, so locally built
        outputs are repaired before first use. Any existing
        `nix.settings.post-build-hook` is auto-detected and chained (you
        do not need to move it); add further hooks with
        {option}`services.machokeeper.extraPostBuildHooks`.

        Off by default on home-manager: `post-build-hook` is a trusted,
        daemon-side setting, so a user-level nix.conf cannot set it on a
        multi-user install. Use the nix-darwin or NixOS module for the
        hook.
      '';
    };

    extraPostBuildHooks = lib.mkOption {
      type = lib.types.listOf (lib.types.either lib.types.path lib.types.str);
      default = [ ];
      example = lib.literalExpression ''[ "''${pkgs.cachix}/bin/cachix-push-hook" ]'';
      description = ''
        Additional post-build-hook programs to run after machokeeper's,
        for hooks not expressed through `nix.settings.post-build-hook`
        (which is auto-chained). Each runs fail-open with the same
        environment and arguments.
      '';
    };

    chainPostBuildHook = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      visible = false; # superseded by auto-detection + extraPostBuildHooks
      description = ''
        Deprecated: an existing post-build-hook to run after
        machokeeper's. No longer needed — a hook set via
        `nix.settings.post-build-hook` is auto-chained. Kept for
        compatibility; prefer
        {option}`services.machokeeper.extraPostBuildHooks`.
      '';
    };

    scanOnActivation = lib.mkOption {
      type = lib.types.bool;
      default = platform != "home";
      defaultText = lib.literalExpression ''platform != "home"'';
      description = ''
        Scan the incoming generation's new store paths during
        activation (after substitution, before the generation goes
        live) and act per {option}`onActivation`. Not available on
        home-manager (activation runs unprivileged and cannot write the
        store); see {option}`services.machokeeper.detectOnActivation`.
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
      default = platform != "home";
      defaultText = lib.literalExpression ''platform != "home"'';
      description = ''
        The first time machokeeper activates, sweep the whole store
        once to repair anything already broken. Subsequent activations
        only scan the generation delta. A marker file records that the
        sweep has run. Not available on home-manager (unprivileged
        activation cannot write the store).
      '';
    };

    detectOnActivation = lib.mkOption {
      type = lib.types.bool;
      default = platform == "home";
      defaultText = lib.literalExpression ''platform == "home"'';
      description = ''
        home-manager only: on activation, scan the home generation's new
        store paths read-only (no privileges needed) and warn if any
        carry a broken Mach-O signature, pointing at
        `sudo machokeeper doctor --fix`. Repair itself needs the
        nix-darwin/NixOS module or root; this gives visibility without
        it.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    let
      marker = "/nix/var/machokeeper/.swept";

      # Privileged repair path (darwin / nixos activation runs as root).
      repairActivation = ''
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
    # `platform` is a static build-time value, so it selects which
    # definitions exist (via lib.optional) — using lib.mkIf for it would
    # leak `home.*` into the option tree on nixos/darwin (and vice
    # versa). Config-value conditions (cfg.*) stay as lib.mkIf inside.
    lib.mkMerge (
      # The CLI on PATH.
      lib.optional (platform == "home") { home.packages = [ machokeeper ]; }
      ++ lib.optional (platform != "home") { environment.systemPackages = [ machokeeper ]; }

      # post-build-hook: darwin / nixos only (see postBuildHook doc).
      # Appended after nix.settings, so this wins the single
      # post-build-hook slot while the dispatcher chains the prior one.
      ++ lib.optional (platform != "home") (
        lib.mkIf cfg.postBuildHook { nix.extraOptions = "post-build-hook = ${dispatcher}"; }
      )

      # nix-darwin, unlike NixOS, has no generic activation-script dag: its
      # `activate` splices only a fixed, enumerated set of script names
      # (preActivation … postActivation). A custom `activationScripts.<name>`
      # evaluates fine but is silently never run. So append into
      # postActivation — which still runs before the current-system symlink
      # flips — where `$systemConfig` is already in scope.
      ++ lib.optional (platform == "darwin") (
        lib.mkIf cfg.scanOnActivation {
          system.activationScripts.postActivation.text = lib.mkAfter repairActivation;
        }
      )

      ++ lib.optional (platform == "nixos") (
        lib.mkIf cfg.scanOnActivation {
          system.activationScripts.machokeeper = ''
            systemConfig="''${systemConfig:-$(readlink -f /run/current-system)}"
            ${repairActivation}
          '';
        }
      )

      # home-manager: read-only detection (repair needs the system
      # module or sudo — an unprivileged activation cannot write /nix).
      ++ lib.optional (platform == "home") (
        lib.mkIf cfg.detectOnActivation {
          home.activation.machokeeper = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
            if ! ${bin} check "''${HOME}/.nix-profile" 2>/dev/null; then
              run echo "machokeeper: broken Mach-O signatures in your profile; run: sudo ${bin} doctor --fix ~/.nix-profile"
            fi
          '';
        }
      )
    )
  );
}
