{
  perSystem =
    { pkgs, ... }:
    {
      devShells.default = pkgs.mkShellNoCC {
        GOROOT = "${pkgs.go}/share/go";
        CGO_ENABLED = "0";

        packages = with pkgs; [

          # go tools
          delve
          go
          golangci-lint
          gopls
          gotools

          # misc tools
          gnumake
          gawk
          watchexec
        ];
      };
    };
}
