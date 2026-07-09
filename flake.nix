{
  description = "Keep your Nix store's Mach-O binaries valid";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Used only by the darwin-only activation eval check (below): nix-darwin
    # has no generic activation-script dag, so the module must land its scan
    # in a slot `activate` actually splices. The check builds a darwinSystem
    # and asserts the snippet is present. Not a runtime dependency of the
    # module — consumers supply their own nix-darwin.
    nix-darwin = {
      url = "github:nix-darwin/nix-darwin";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      nix-darwin,
    }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      # One formatter tree for every language in the repo: `nix fmt`
      # writes, the treefmt flake check verifies. gofmt stays the Go
      # authority (the same formatting CI's gofmt gate demands).
      treefmtFor =
        system:
        treefmt-nix.lib.evalModule nixpkgs.legacyPackages.${system} {
          projectRootFile = "flake.nix";
          programs = {
            gofmt.enable = true;
            nixfmt.enable = true;
            ruff-format.enable = true;
            shfmt.enable = true;
            yamlfmt = {
              enable = true;
              settings.formatter.retain_line_breaks_single = true;
            };
          };
          # The vendored oracle stays byte-comparable with its C++-era
          # ancestor; don't reformat it.
          settings.global.excludes = [ "internal/oracle/*.py" ];
        };
    in
    {
      formatter = forAllSystems (system: (treefmtFor system).config.build.wrapper);

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        rec {
          machokeeper = pkgs.buildGoModule {
            pname = "machokeeper";
            version = "0.1.0";
            src = self;
            vendorHash = null;
            # The oracle cross-validation test needs python3; run it
            # in CI, not in the sandboxed nix build.
            doCheck = false;
            meta = {
              description = "Keep your Nix store's Mach-O binaries valid";
              homepage = "https://github.com/machokeeper/machokeeper";
              license = pkgs.lib.licenses.mit;
              mainProgram = "machokeeper";
            };
          };
          default = machokeeper;
        }
      );

      # The full verification triad needs more than the build env:
      # golangci-lint for the lint gate and python3 for the oracle
      # cross-validation test (which silently skips without it).
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              golangci-lint
              python3
              gitleaks
              actionlint
              statix
              deadnix
            ];
          };
        }
      );

      # `nix flake check` is the one-command local gate: package build,
      # whole-tree formatting (treefmt), unit tests + oracle, vet,
      # golangci-lint, secrets scan, workflow lint, and nix-file
      # hygiene. CI runs the same command.
      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          src = self;
          goEnv = ''
            export HOME=$TMPDIR GOCACHE=$TMPDIR/gocache GOPATH=$TMPDIR/gopath GOPROXY=off GOFLAGS=-mod=mod
          '';
        in
        {
          package = self.packages.${system}.default;

          # Whole-tree formatting (nix fmt to fix).
          treefmt = (treefmtFor system).config.build.check self;

          tests =
            pkgs.runCommand "go-tests"
              {
                nativeBuildInputs = [
                  pkgs.go
                  pkgs.python3
                ];
              }
              ''
                cp -r ${src} src && chmod -R +w src && cd src
                ${goEnv}
                export MACHOKEEPER_REQUIRE_ORACLE=1
                go vet ./...
                go test ./...
                touch $out
              '';

          lint =
            pkgs.runCommand "golangci-lint"
              {
                nativeBuildInputs = [
                  pkgs.go
                  pkgs.golangci-lint
                ];
              }
              ''
                cp -r ${src} src && chmod -R +w src && cd src
                ${goEnv}
                export GOLANGCI_LINT_CACHE=$TMPDIR/lintcache
                golangci-lint run --timeout 5m
                touch $out
              '';

          secrets = pkgs.runCommand "gitleaks" { nativeBuildInputs = [ pkgs.gitleaks ]; } ''
            gitleaks detect --source ${src} --no-git --redact
            touch $out
          '';

          actionlint = pkgs.runCommand "actionlint" { nativeBuildInputs = [ pkgs.actionlint ]; } ''
            # No .git in the store copy: name the workflow files explicitly.
            actionlint ${src}/.github/workflows/*.yml
            touch $out
          '';

          nix-hygiene =
            pkgs.runCommand "nix-hygiene"
              {
                nativeBuildInputs = [
                  pkgs.statix
                  pkgs.deadnix
                ];
              }
              ''
                statix check ${src}
                deadnix --fail ${src}
                touch $out
              '';
        }
        # Linux-only checks: the NixOS VM nix-daemon integration test
        # (needs KVM; CI's ubuntu runners have it) and the module
        # post-build-hook auto-chaining eval (needs nixosSystem).
        // nixpkgs.lib.optionalAttrs (nixpkgs.lib.hasSuffix "-linux" system) {
          vm-nixstore = import ./nix/vm-test.nix { inherit pkgs self; };
          module-autochain = import ./nix/module-test.nix { inherit pkgs self nixpkgs; };
        }
        # Darwin-only: prove the activation scan/sweep lands in nix-darwin's
        # `activate` (which splices only a fixed set of script names).
        // nixpkgs.lib.optionalAttrs (nixpkgs.lib.hasSuffix "-darwin" system) {
          module-darwin-activation = import ./nix/module-darwin-test.nix {
            inherit
              pkgs
              self
              nix-darwin
              system
              ;
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/machokeeper";
          meta.description = "Diagnose and repair broken Mach-O signatures in a Nix store";
        };
      });

      darwinModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        import ./nix/module-common.nix {
          inherit
            config
            lib
            pkgs
            self
            ;
          platform = "darwin";
        };

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        import ./nix/module-common.nix {
          inherit
            config
            lib
            pkgs
            self
            ;
          platform = "nixos";
        };

      homeManagerModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        import ./nix/module-common.nix {
          inherit
            config
            lib
            pkgs
            self
            ;
          platform = "home";
        };
    };
}
