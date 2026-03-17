# Progress Log

## Status
Bootstrap, Linux-hosted RFC 7030 EST validation, exhaustive QA, and RPM packaging completed for the current development phase.

## Completed Work
- Initialized Rust binary crate `est-server`
- Created required project directories:
  - `src/bin/`
  - `src/config/`
  - `src/est/`
  - `demo/`
  - `logs/`
  - `.github/workflows/`
  - `memory-bank/`
- Replaced generated `Cargo.toml` with a strict system-OpenSSL configuration
- Added `build.rs` to:
  - detect OpenSSL 3.x
  - enforce explicit `ssl` and `crypto` linkage
- Implemented `src/main.rs` bootstrap/configuration utility with:
  - OpenSSL runtime and CLI version detection
  - FIPS provider detection
  - ML-KEM detection
  - ML-DSA detection
  - interactive selection for key type
  - interactive selection for TLS 1.3 cipher suite
  - interactive selection for listening port
  - optional FIPS enablement when available
  - TOML config generation
  - environment logging
- Implemented EST HTTPS server behavior in `src/est/mod.rs`
- Implemented demo-key generation in `src/bin/generate-demo-keys.rs`
- Implemented a local EST validation client in `src/bin/test-client.rs`
- Updated the test client to validate a Linux-hosted EST server by using `curl --resolve` for IP-based targets and binary-safe multipart parsing for `serverkeygen`
- Expanded the EST server to persist enrollment CSRs and issued certificates under `logs/enrollments/`
- Expanded the EST server to persist deferred enrollment state under `logs/pending/`
- Implemented RFC 7030 deferred `202 Accepted` plus `Retry-After` handling for enrollment operations
- Implemented stricter `simplereenroll` subject and subjectAltName matching validation
- Fixed Linux-hosted `cacerts` failures by making OpenSSL binary selection fall back safely when a configured absolute path does not exist on the remote host
- Fixed Linux QA restarts by replacing stale deleted EST server listeners with the rebuilt remote binary
- Fixed remote `serverkeygen` artifact validation so QA checks server-generated key semantics correctly
- Expanded the EST runtime configuration model to include bind address, CA/TLS file paths, client-auth trust anchor path, storage directories, request-size limits, and deferred retry timing
- Added CLI override support for all administrator-facing EST runtime settings
- Added `config.toml.example` with commented administrator guidance and a known-good demo-backed configuration
- Added `est-server.service.example` with a known-good demo deployment unit and documented override usage
- Adjusted normal server startup so runtime mode only prepares writable runtime directories instead of development-only project directories
- Updated RPM packaging metadata in `Cargo.toml`
- Generated `config.toml`
- Generated `logs/env-check.log`
- Synced the project to Linux host `192.168.200.120`
- Installed the Rust toolchain and `cargo-generate-rpm` on Linux host `192.168.200.120`
- Ran the EST server persistently on Linux host `192.168.200.120` under `tmux`
- Produced local EST validation evidence files under `logs/`
- Pulled the built RPM artifact back to the local workspace as `est-server-0.1.0-1.x86_64.rpm`

## Validation Results
Validated successfully with:
- local `cargo build --release`
- local `cargo build --release --bin test-client`
- local `./target/release/test-client --validate-all --base-url https://192.168.200.120:8443`
- local `cargo run --release --bin test-client -- --validate-all --base-url https://192.168.200.120:8443 --ssh-host krich@192.168.200.120`
- Linux-host `cargo build --release --locked`
- Linux-host `cargo test`
- Linux-host `cargo generate-rpm`
- local `./target/release/est-server --config ./config.toml.example`
- local `./target/release/est-server --config ./config.toml --listen-address 127.0.0.1`
- Linux-host staged `/opt/est-server` deployment using `config.toml.example`
- Linux-host `systemd-analyze verify /tmp/est-server.service`

Local macOS validation used:
- `OPENSSL_DIR=/opt/homebrew/opt/openssl@3.5`
- `OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3.5/lib`
- `OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3.5/include`
- `PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3.5/lib/pkgconfig`

Linux-host validation on `192.168.200.120` used:
- system OpenSSL `3.0.2`
- Rust toolchain installed with `rustup`
- persistent EST server session managed with `tmux`
- final remote QA passed with the rebuilt EST server listening from `/home/krich/src/est-rust-server/target/release/est-server`

## Environment Findings
- Local macOS host uses OpenSSL 3.5.4 and supports PQ algorithms including ML-KEM and ML-DSA
- Linux host `192.168.200.120` is Ubuntu 22.04.5 with system OpenSSL `3.0.2`
- FIPS provider is not available on the current hosts
- Current local host is macOS `aarch64`
- RFC 7030 EST server testing, QA, and RPM packaging are now being executed on Linux host `192.168.200.120`
- The local system is the execution point for the EST validation client and targets the Linux-hosted EST server remotely
- Linux OpenSSL `3.0.2` does not support `ML-DSA-87`, so `config.toml` was adjusted to `key_type = "rsa2048"` for Linux-hosted `serverkeygen` validation

## Generated Configuration Snapshot
```toml
listen_port = 8443
tls_version = "TLS1.3"
preferred_tls_cipher_suite = "TLS_AES_256_GCM_SHA384"
key_type = "rsa2048"
enable_fips = false
openssl_dir = "/opt/homebrew/opt/openssl@3.5"
openssl_binary = "/opt/homebrew/opt/openssl@3.5/bin/openssl"
ml_kem_supported = true
ml_dsa_supported = false
```

## Recommendations
- For Linux FIPS enablement, install and activate the OpenSSL FIPS provider before enabling FIPS mode
- Keep the EST server on Linux host `192.168.200.120` for every RFC 7030 implementation, testing, and QA stage
- Keep the test client on the local development system while connecting to the EST server on `192.168.200.120`
- Treat local macOS builds as development-only compile checks
- Upgrade the Linux host OpenSSL if PQ server-generated key algorithms such as ML-DSA must be validated there

## Next Step
Proceed to release publication and any remaining Git tagging or GitHub release automation using the Linux-built RPM artifact, the successful Linux-hosted EST validation results, `demo/validation-report.md`, `config.toml.example`, and `est-server.service.example`.
