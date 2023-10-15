{ pkgs ? import <nixpkgs> { } }: pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    rustup
    gcc
    clang_16
    nasm
    gnumake
  ];
  shellHook = ''
    export PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
  '';
  packages = (with pkgs; [
    binutils
    gef
    shellcheck
  ]);
}
