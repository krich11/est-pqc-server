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
- Server-side persistence of enrollment artifacts
- Configurable runtime through both:
  - config file
  - command-line arguments
- Demo PKI materials and validation client included
- RPM generation support for Linux deployment

## Repository Layout

- `src/main.rs` - bootstrap, config tool, and runtime entrypoint
- `src/est/mod.rs` - EST server implementation
- `src/bin/generate-demo-keys.rs` - demo key and certificate generation
- `src/bin/test-client.rs` - EST validation client
- `config.toml.example` - documented sample configuration
- `est-server.service.example` - sample systemd unit
- `demo/` - demo CA, client, and server certificates
- `memory-bank/` - project status and architecture notes

## Requirements

- Rust toolchain
- OpenSSL 3.x system library and CLI
- `pkg-config`
- Linux for authoritative build, QA, and packaging
- macOS may be used for local editing and compile checks

## Build

```sh
cargo build --release
```

## Run

Using the sample config:

```sh
./target/release/est-server --config ./config.toml.example
```

Using config plus CLI overrides:

```sh
./target/release/est-server \
  --config ./config.toml \
  --listen-address 127.0.0.1 \
  --listen-port 8443
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

See `config.toml.example` for a documented known-good sample.

## Demo and Validation

Generate demo materials:

```sh
cargo run --release --bin generate-demo-keys
```

Run validation:

```sh
cargo run --release --bin test-client -- --validate-all --base-url https://127.0.0.1:8443
```

The project also includes Linux-host validation against a remote test host and a generated validation report in `demo/validation-report.md`.

## systemd Deployment

A sample unit file is provided at `est-server.service.example`.

Known-good demo deployment notes:

- the sample unit uses `User=root`
- this is intentional for the demo setup because the provided demo CA private key is root-owned
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
- The Linux validation host currently uses OpenSSL 3.0.2, so PQC algorithms are not available there.

## License

MIT