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
        ndn-fwd = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "ndn-fwd";
          cargoExtraArgs = "--bin ndn-fwd";
          meta.mainProgram = "ndn-fwd";
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
          inherit ndn-fwd ndn-tools ndn-bench;
          default = ndn-fwd;
        };

        # ── Checks (CI) ────────────────────────────────────────────────────

        checks = {
          inherit ndn-fwd ndn-tools ndn-bench;

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
          cfg = config.services.ndn-fwd;
          toolsPkg = self.packages.${pkgs.system}.ndn-tools;
          # Resolved PIB path — either user-supplied or under the state directory.
          resolvedPibPath = if cfg.pibPath != null
            then cfg.pibPath
            else "/var/lib/ndn-fwd/pib";
        in {
          options.services.ndn-fwd = {
            enable = lib.mkEnableOption "NDN router (ndn-rs forwarder)";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.ndn-fwd;
              defaultText = lib.literalExpression "inputs.ndn-rs.packages.\${system}.ndn-fwd";
              description = "The ndn-fwd package to use.";
            };

            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "Path to ndn-fwd TOML configuration file.";
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

            # ── Key management ──────────────────────────────────────────────

            identity = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "/ndn/mysite/router1";
              description = ''
                NDN identity name for this router (e.g. <literal>/ndn/mysite/router1</literal>).

                When set together with <option>generateIdentity = true</option> (the default),
                a persistent Ed25519 key and self-signed certificate are generated on first
                boot and stored in <option>pibPath</option>.  Subsequent starts reuse the
                existing key without overwriting it.

                On NixOS the system root is read-only, so keys must live in a writable
                location such as the state directory.  Leave this unset to let the router
                use an ephemeral in-memory key (useful for testing).
              '';
            };

            pibPath = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              defaultText = lib.literalExpression ''"''\${config.services.ndn-fwd.stateDir}/pib"'';
              example = "/var/lib/ndn-fwd/pib";
              description = ''
                Path to the PIB directory that stores Ed25519 keys.

                Defaults to <filename>/var/lib/ndn-fwd/pib</filename> (the service
                state directory), which is writable even on NixOS immutable roots.
                Set this if you want to share a single PIB across multiple routers or
                store keys on an encrypted partition.
              '';
            };

            generateIdentity = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Auto-generate the <option>identity</option> key on first boot if it does
                not already exist in the PIB.

                Uses <command>ndn-sec keygen --anchor --skip-if-exists</command> as an
                <literal>ExecStartPre</literal> step so the operation is idempotent:
                subsequent restarts detect the existing key and skip generation silently.

                Has no effect when <option>identity</option> is null.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            # Firewall rules for standard NDN port.
            networking.firewall = lib.mkIf cfg.openFirewall {
              allowedUDPPorts = [ 6363 ];
              allowedTCPPorts = [ 6363 ];
            };

            systemd.services.ndn-fwd = {
              description = "NDN Forwarder (ndn-rs)";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];

              environment = {
                RUST_LOG = cfg.logLevel;
                # Expose the PIB path so ndn-fwd picks it up via $NDN_PIB even
                # when the user's config file does not set pib_path explicitly.
                NDN_PIB = resolvedPibPath;
              };

              serviceConfig = {
                ExecStart =
                  let
                    args = lib.optionalString (cfg.configFile != null)
                      " -c ${cfg.configFile}";
                  in
                    "${cfg.package}/bin/ndn-fwd${args}";

                # Idempotent key generation: run before the forwarder starts.
                # ndn-sec --skip-if-exists is a no-op when the key already exists,
                # so this is safe to run on every boot without overwriting keys.
                ExecStartPre = lib.optional
                  (cfg.identity != null && cfg.generateIdentity)
                  (lib.escapeShellArgs [
                    "${toolsPkg}/bin/ndn-sec"
                    "--pib" resolvedPibPath
                    "keygen"
                    "--anchor"
                    "--skip-if-exists"
                    cfg.identity
                  ]);

                Restart = "on-failure";
                RestartSec = 5;

                # Hardening.
                # DynamicUser=true is intentionally NOT set here so that the
                # ExecStartPre key-generation step and the router process share a
                # stable UID that can own /var/lib/ndn-fwd consistently.
                # The state directory is created and owned by systemd automatically.
                User = "ndn-fwd";
                Group = "ndn-fwd";
                StateDirectory = "ndn-fwd";
                RuntimeDirectory = "ndn-fwd";
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

            # Stable UID/GID for the router service (required since DynamicUser=false).
            users.users.ndn-fwd = {
              isSystemUser = true;
              group = "ndn-fwd";
              description = "NDN router service account";
              home = "/var/lib/ndn-fwd";
            };
            users.groups.ndn-fwd = {};
          };
        };
    };
}
