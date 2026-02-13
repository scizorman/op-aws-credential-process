{
  description = "AWS credential_process helper that retrieves credentials from 1Password with MFA session caching";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.gofmt.enable = true;
          programs.nixfmt.enable = true;
        };
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "op-aws-credential-helper";
          version = "0.1.0";
          src = ./.;
          vendorHash = null;
        };

        formatter = treefmtEval.config.build.wrapper;
        checks.formatting = treefmtEval.config.build.check self;

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_1_26
          ];
        };
      }
    );
}
