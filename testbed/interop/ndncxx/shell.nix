# ndn-cxx (with `ndnsec`) and the build inputs of ndncxx-interop.cpp, for
# check.sh / c07_certv2_ndncxx_interop.sh. Witnessed with nixpkgs ndn-cxx 0.9.0.
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = with pkgs; [ ndn-cxx boost openssl sqlite pkg-config ];
}
