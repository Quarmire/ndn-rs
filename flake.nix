{
  description = "ndn-rs — Named Data Networking forwarder stack in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Rust toolchain — edition 2024 requires >= 1.85.
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common source filtering — only include Rust/Cargo files and docs.
        src = craneLib.cleanCargoSource ./.;

        # Shared arguments for all crane builds.
        commonArgs = {
          inherit src;
          strictDeps = true;

          # Native dependencies needed at build time.
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          # Runtime / linking dependencies.
          buildInputs = with pkgs; [
            openssl # for tokio-tungstenite native-tls
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
            pkgs.apple-sdk_15
            pkgs.libiconv
          ];
        };

        # Build workspace dependencies first (cached across rebuilds).
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Individual binary packages.
        ndn-router = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "ndn-router";
          cargoExtraArgs = "--bin ndn-router";
          meta.mainProgram = "ndn-router";
        });

        ndn-tools = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "ndn-tools";
          cargoExtraArgs = builtins.concatStringsSep " " [
            "--bin ndn-peek"
            "--bin ndn-put"
            "--bin ndn-ping"
            "--bin ndn-sec"
            "--bin ndn-ctl"
            "--bin ndn-traffic"
            "--bin ndn-iperf"
          ];
        });

        ndn-bench = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "ndn-bench";
          cargoExtraArgs = "--bin ndn-bench";
          meta.mainProgram = "ndn-bench";
        });

      in {
        # ── Packages ────────────────────────────────────────────────────────

        packages = {
          inherit ndn-router ndn-tools ndn-bench;
          default = ndn-router;
        };

        # ── Checks (CI) ────────────────────────────────────────────────────

        checks = {
          inherit ndn-router ndn-tools ndn-bench;

          workspace-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "-- -D warnings";
          });

          workspace-fmt = craneLib.cargoFmt {
            inherit src;
          };

          workspace-test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });
        };

        # ── Dev shell ───────────────────────────────────────────────────────

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};

          packages = with pkgs; [
            # Rust toolchain is provided by crane's devShell.
            cargo-watch
            cargo-nextest
          ];

          # Environment variables useful during development.
          RUST_LOG = "info";
        };
      }
    )

    //

    # ── NixOS module ──────────────────────────────────────────────────────────

    {
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.ndn-router;
        in {
          options.services.ndn-router = {
            enable = lib.mkEnableOption "NDN router (ndn-rs forwarder)";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.ndn-router;
              defaultText = lib.literalExpression "inputs.ndn-rs.packages.\${system}.ndn-router";
              description = "The ndn-router package to use.";
            };

            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "Path to ndn-router TOML configuration file.";
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Open UDP/TCP port 6363 in the firewall.";
            };

            logLevel = lib.mkOption {
              type = lib.types.str;
              default = "info";
              description = "RUST_LOG filter string.";
            };
          };

          config = lib.mkIf cfg.enable {
            # Firewall rules for standard NDN port.
            networking.firewall = lib.mkIf cfg.openFirewall {
              allowedUDPPorts = [ 6363 ];
              allowedTCPPorts = [ 6363 ];
            };

            systemd.services.ndn-router = {
              description = "NDN Router (ndn-rs)";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];

              environment = {
                RUST_LOG = cfg.logLevel;
              };

              serviceConfig = {
                ExecStart =
                  let
                    args = lib.optionalString (cfg.configFile != null)
                      " -c ${cfg.configFile}";
                  in
                    "${cfg.package}/bin/ndn-router${args}";

                Restart = "on-failure";
                RestartSec = 5;

                # Hardening.
                DynamicUser = true;
                StateDirectory = "ndn-router";
                RuntimeDirectory = "ndn-router";
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                NoNewPrivileges = true;
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                RestrictSUIDSGID = true;
                MemoryDenyWriteExecute = true;

                # Capabilities for raw sockets (Ethernet faces) and
                # binding to privileged ports.
                AmbientCapabilities = [
                  "CAP_NET_RAW"
                  "CAP_NET_BIND_SERVICE"
                ];
                CapabilityBoundingSet = [
                  "CAP_NET_RAW"
                  "CAP_NET_BIND_SERVICE"
                ];
              };
            };
          };
        };
    };
}
