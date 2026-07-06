{
  description = "Keep your Nix store's Mach-O binaries valid";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
    in
    {
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

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/machokeeper";
          meta.description = "Diagnose and repair broken Mach-O signatures in a Nix store";
        };
      });

      darwinModules.default =
        { config, lib, pkgs, ... }:
        import ./nix/module-common.nix {
          inherit config lib pkgs self;
          platform = "darwin";
        };

      nixosModules.default =
        { config, lib, pkgs, ... }:
        import ./nix/module-common.nix {
          inherit config lib pkgs self;
          platform = "nixos";
        };

      homeManagerModules.default =
        { config, lib, pkgs, ... }:
        import ./nix/module-common.nix {
          inherit config lib pkgs self;
          platform = "home";
        };
    };
}
