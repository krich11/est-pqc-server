# Project Brief

## Project
EST Rust Server for a strictly RFC 7030-compliant Enrollment over Secure Transport server, with exhaustive QA and no omitted protocol behaviors.

## Scope
Deliver a production-grade EST server that enforces strict RFC 7030 behavior for every supported operation and response path, using only the system OpenSSL 3 library. Scope includes:
- complete EST endpoint behavior for `cacerts`, `csrattrs`, `simpleenroll`, `simplereenroll`, and `serverkeygen`
- exact RFC 7030 media types, response codes, retry behavior, and message formatting
- mutual TLS enforcement where required
- proof-of-possession linkage validation
- server-side persistence of received CSRs and issued certificates
- validation of returned certificates and persisted server-side enrollment artifacts
- exhaustive QA covering all implemented outputs, protocol paths, and negative cases
- repeated fix-and-retest cycles until the QA workflow passes cleanly

## Bootstrap Summary
Bootstrap completed for the initial configuration phase.

### Completed
- Rust binary project initialized as `est-server`
- Required directories created:
  - `src/bin/`
  - `src/config/`
  - `src/est/`
  - `demo/`
  - `logs/`
  - `.github/workflows/`
  - `memory-bank/`
- `Cargo.toml` created with system-OpenSSL-only configuration
- `build.rs` created to enforce OpenSSL 3.x detection and explicit `ssl`/`crypto` linking
- `src/main.rs` implemented as a menu-driven configuration tool using `dialoguer` and `ratatui`
- `config.toml` generated
- `logs/env-check.log` generated
- Validation completed with:
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - `cargo build --release`

## Environment Detection Summary
- Runtime OpenSSL: `OpenSSL 3.5.4 30 Sep 2025`
- CLI OpenSSL: `OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025)`
- OpenSSL binary: `/opt/homebrew/opt/openssl@3.5/bin/openssl`
- OpenSSL directory: `/opt/homebrew/opt/openssl@3.5`
- Architecture: `aarch64`
- Operating system: `macos`
- `pkg-config` available: `true`
- FIPS requested: `false`
- FIPS available: `false`
- ML-KEM supported: `true`
- ML-DSA supported: `true`

## Current Configuration
```toml
listen_port = 8443
tls_version = "TLS1.3"
preferred_tls_cipher_suite = "TLS_AES_256_GCM_SHA384"
key_type = "ml-dsa87"
enable_fips = false
openssl_dir = "/opt/homebrew/opt/openssl@3.5"
openssl_binary = "/opt/homebrew/opt/openssl@3.5/bin/openssl"
ml_kem_supported = true
ml_dsa_supported = true
```

## Current Constraints
- FIPS provider is not available on the current host
- Current host is macOS, while RFC 7030 EST server testing, QA, and packaging are required to run on the Linux host `192.168.200.120` at every stage

## Workflow Policy Update
- RFC 7030 server testing and QA must be performed on the Linux host `192.168.200.120` during all implementation stages, not only at final release time
- The EST server under test must run on the Linux host `192.168.200.120`
- The test client must run on the local development system and connect remotely to the EST server on `192.168.200.120`
- Local macOS builds may be used for editing and fast compile checks only; they are not the authoritative QA environment
- Remote Linux validation must cover iterative EST endpoint verification, regression testing, and RPM packaging readiness throughout development

## Completion Summary
- RFC 7030 EST endpoint coverage was expanded and validated for:
  - `cacerts`
  - `csrattrs`
  - `simpleenroll`
  - `simplereenroll`
  - `serverkeygen`
- Aggressive QA now covers:
  - successful enrollment responses
  - `202 Accepted` plus `Retry-After` retry behavior
  - returned certificate validation
  - persisted server-side CSR and certificate validation
  - negative protocol and content-type cases
  - reenrollment subject and subjectAltName matching rules
  - multipart `serverkeygen` certificate and encrypted-key validation
- Final Linux-hosted remote QA passed cleanly against `https://192.168.200.120:8443`
- Linux-host restart handling was corrected to replace stale deleted binaries before validation
- Linux-host OpenSSL path handling was corrected so remote runtime falls back safely to the system `openssl` binary when macOS-specific configured paths do not exist

## Administrator Configuration Completion
- The EST runtime now supports administrator-facing configuration for:
  - bind address and port
  - TLS cipher suite
  - OpenSSL install root and CLI binary
  - issuing CA certificate and private key paths
  - client-auth trust anchor path
  - TLS server certificate and private key paths
  - enrollment and pending storage directories
  - maximum request body size
  - default deferred Retry-After timing
  - recorded ML-KEM and ML-DSA capability flags
- Every supported runtime setting can now be supplied through either:
  - the config file
  - command-line arguments
- Added deployment artifacts for administrators:
  - `config.toml.example`
  - `est-server.service.example`
- Verified:
  - local runtime startup using `config.toml.example`
  - local runtime startup using `config.toml` plus CLI overrides
  - Linux-host staged deployment under `/opt/est-server`
  - Linux-host `systemd-analyze verify` against a staged service unit
  - Linux-host EST endpoint success for `csrattrs` using the staged deployment

## Repository Publication Completion
- Added `README.md` with project overview, build/run instructions, validation workflow, configuration summary, deployment notes, and packaging guidance
- Created the public GitHub repository `https://github.com/krich11/est-pqc-server`
- Committed the local project as `Initial est-pqc-server import`
- Pushed the local `main` branch to `origin`

## Immediate Next Phase
- Proceed with tagged releases, GitHub Releases publication, and continued feature work from `https://github.com/krich11/est-pqc-server`
- Use the Linux-built RPM artifact, `demo/validation-report.md`, `config.toml.example`, and `est-server.service.example` as the current release evidence set
