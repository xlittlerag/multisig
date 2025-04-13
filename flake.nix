{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    foundry.url = "github:shazow/foundry.nix/monthly"; # Use monthly branch for permanent releases
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
      foundry,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ foundry.overlay ];
        };
      in
      {

        devShell =
          with pkgs;
          mkShell {
            buildInputs = [
              foundry-bin
              solc
            ];

            shellHook = ''
              export FOUNDRY_SOLC="${pkgs.solc}/bin/solc"
              exec zsh
            '';
          };
      }
    );
}
