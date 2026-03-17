# est-pqc-server

A Rust-based Enrollment over Secure Transport (EST) server aligned to RFC 7030, using the system OpenSSL 3 library only.

## Features

- EST endpoints:
  - `/.well-known/est/cacerts`
  - `/.well-known/est/csrattrs`
  - `/.well-known/est/simpleenroll`
  - `/.well-known/est/simplereenroll`
  - `/.well-known/est/serverkeygen`
- TLS 1.3-only listener
- Mutual TLS enforcement for enrollment operations
- PKCS#7 and CMS response generation via system OpenSSL
- Deferred enrollment handling with `202 Accepted` and `Retry-After`
- Policy-driven enrollment authorization with per-request rule matching
- Manual approval workflow backed by persisted pending-enrollment records
- Embedded HTTPS WebUI for:
  - runtime status
  - effective config and enrollment rules
  - pending approval queue and issued-enrollment history
  - approve/reject actions for queued EST requests
  - basic `systemd` status and start/stop/restart actions
- Server-side persistence of enrollment artifacts
- Configurable runtime through both:
  - config file
  - command-line arguments
- Demo PKI materials and validation client included
- RPM generation support for Linux deployment

## Repository Layout

- `src/main.rs` - bootstrap, config tool, CLI overrides, and runtime entrypoint
- `src/est/mod.rs` - EST server, enrollment policy evaluation, pending queue, and issuance logic
- `src/webui/mod.rs` - embedded WebUI backend and API surface
- `src/bin/generate-demo-keys.rs` - demo key and certificate generation
- `src/bin/test-client.rs` - EST validation client
- `config.toml` - runtime configuration
- `webui/static/` - embedded WebUI frontend assets
- `demo/` - demo CA, client, and server certificates
- `memory-bank/` - project status and architecture notes

## Requirements

- Rust toolchain
- OpenSSL 3.x system library and CLI
- `pkg-config`

## Build

```sh
cargo build --release
```

## Run

Using the current config:

```sh
./target/release/est-server --config ./config.toml
```

Using config plus CLI overrides:

```sh
./target/release/est-server \
  --config ./config.toml \
  --listen-address 127.0.0.1 \
  --listen-port 8443 \
  --webui-enabled \
  --webui-listen-address 127.0.0.1 \
  --webui-listen-port 9443
```

## Configuration

The server supports the following administrator-facing settings in both config file and CLI form:

- bind address and port
- TLS version and preferred cipher suite
- OpenSSL directory and binary path
- CA certificate and CA private key paths
- client-auth trust anchor path
- TLS certificate and TLS private key paths
- enrollment and pending storage directories
- maximum request body size
- default `Retry-After` value
- ML-KEM and ML-DSA capability flags
- WebUI enablement, bind address, port, TLS certificate, and TLS private key
- WebUI authentication mode:
  - `basic`
  - `mtls`
- WebUI admin username and Argon2 password hash
- WebUI-managed `systemd` unit name
- enrollment authorization defaults and rule list under `[enrollment]`

Example rule model:

```toml
[enrollment]
default_action = "auto"

[[enrollment.rules]]
name = "approve engineering csr requests manually"
match_subject_ou = "^Engineering$"
action = "manual"

[[enrollment.rules]]
name = "reject unexpected issuer"
match_client_cert_issuer = "CN=Untrusted"
action = "reject"
reject_reason = "client issuer is not authorized"
```

Manual approvals are persisted under `logs/pending/<operation>/<artifact_id>/status.json`.
Issued artifacts are persisted under `logs/enrollments/<operation>/<artifact_id>/`.

## Demo and Validation

Generate demo materials:

```sh
cargo run --release --bin generate-demo-keys
```

Run validation:

```sh
cargo run --release --bin test-client -- --validate-all --base-url https://127.0.0.1:8443
```

Validation now covers:

- EST success paths
- deferred `202 Accepted` flows
- negative RFC 7030 checks
- remote artifact validation over SSH when `--ssh-host` is supplied

The generated validation report is written to `demo/validation-report.md`.

## WebUI

When enabled, the WebUI serves an embedded HTTPS frontend with API endpoints for:

- `GET /api/status`
- `GET /api/config`
- `GET /api/rules`
- `GET /api/enrollment/pending`
- `GET /api/enrollment/history`
- `POST /api/enrollment/pending/:operation/:artifact_id/approve`
- `POST /api/enrollment/pending/:operation/:artifact_id/reject`
- `GET /api/systemd/status`
- `POST /api/systemd/:action`

Basic-auth mode expects the configured admin username and Argon2 password hash.
mTLS mode currently trusts the HTTPS listener and skips additional HTTP auth checks.

## systemd Deployment

Configure the deployed unit name in `webui.systemd_unit_name` if WebUI-managed service actions are needed.

Known-good demo deployment notes:

- the sample/demo deployment uses root-owned demo CA material
- this is intentional for the demo setup
- for production, replace the demo credentials and run under a dedicated service account

## Packaging

Generate an RPM on Linux:

```sh
cargo generate-rpm
```

## Notes

- This project uses the system OpenSSL 3 library only.
- No vendored OpenSSL or alternate crypto provider is used.
- FIPS mode depends on host OpenSSL provider availability.
- PQC capabilities used by this project require OpenSSL 3.5 or later.

## License

MIT