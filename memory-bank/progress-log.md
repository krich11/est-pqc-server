# Progress Log

## Status
Bootstrap, Linux-hosted RFC 7030 EST validation, exhaustive QA, RPM packaging, and the WebUI/manual-approval administration phase completed for the current development phase.

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
- Added `README.md` covering features, layout, build, run, validation, systemd deployment, and packaging
- Created the public GitHub repository `krich11/est-pqc-server`
- Committed the local project as `Initial est-pqc-server import`
- Pushed `main` to `origin` on GitHub
- Updated RPM packaging metadata in `Cargo.toml`
- Generated `config.toml`
- Generated `logs/env-check.log`
- Synced the project to Linux host `192.168.200.120`
- Installed the Rust toolchain and `cargo-generate-rpm` on Linux host `192.168.200.120`
- Ran the EST server persistently on Linux host `192.168.200.120` under `tmux`
- Produced local EST validation evidence files under `logs/`
- Pulled the built RPM artifact back to the local workspace as `est-server-0.1.0-1.x86_64.rpm`
- Added embedded WebUI backend support in `src/webui/mod.rs`
- Added embedded WebUI frontend assets under `webui/static/`
- Added runtime WebUI configuration for listener, TLS files, auth mode, admin credentials, and managed `systemd` unit name
- Added EST enrollment policy configuration with default action and rule-based matching
- Added persisted manual approval records in `logs/pending/<operation>/<artifact_id>/status.json`
- Added WebUI APIs for status, config, rules, pending enrollments, issued enrollment history, and approve/reject operations
- Added WebUI-backed approval flow for `simpleenroll`, `simplereenroll`, and `serverkeygen`
- Updated `README.md` to document WebUI operation, enrollment rules, and manual approval workflow
- Added WebUI certificate store backend support in `src/webui/cert_store.rs`
- Added certificate store APIs for Trusted CA and leaf certificate upload, list, decode/view, and delete
- Added PEM-only Trusted CA storage and P12-only leaf certificate storage under `logs/certificate-store/`
- Added P12 trust validation against the loaded Trusted CA store with the required operator message when trust is unavailable
- Added decoded certificate detail views for Trusted CA and leaf certificates in the WebUI
- Added editable WebUI configuration persistence through `POST /api/config`
- Updated the configuration view to use collapsible sections with persisted collapse state
- Added WebUI certificate store navigation, upload flows, delete flows, and certificate detail drawer rendering
- Updated the certificate store tables so Trusted CA shows `Common Name` first and omits redundant issuer display for self-signed trust anchors
- Added per-leaf certificate service assignment state for `est`, `webui`, or both, persisted in certificate-store metadata and editable from the WebUI

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
- local `cargo check`
- local `cargo test`
- local `node --check webui/static/app.js`
- local `cargo fmt --all --check`
- local `cargo clippy --all-targets -- -D warnings`
- Linux-host staged `/opt/est-server` deployment using `config.toml.example`
- Linux-host `systemd-analyze verify /tmp/est-server.service`
- Linux-host `cargo check`
- Linux-host `cargo test`
- Linux-host `cargo clippy --all-targets -- -D warnings`

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
- QA EST endpoint remains on port `8443`
- QA WebUI endpoint is on port `9443`
- Current QA WebUI access succeeds over `http://192.168.200.120:9443`
- QA service restarts must use `sudo systemctl restart est-server`

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

## Agent Workflow Guardrail: Remote Process Launches
- Do **not** start long-running remote processes over SSH with malformed shell redirection such as HTML-escaped `<` or `>`; the remote shell treats that as literal text and the launch fails.
- Do **not** background a remote process unless stdin, stdout, and stderr are fully detached on the remote side; otherwise the SSH session can remain attached and appear hung in the IDE terminal.
- Do **not** rely on `cmd &` alone for remote persistence. Use a non-interactive SSH invocation plus a fully detached launcher such as `ssh -n ... 'nohup sh -c "... >/tmp/file.log 2>&1 </dev/null" >/dev/null 2>&1 &'`.
- Prefer one-shot verification commands after launch, such as `pgrep`, `ss`, or `curl`, instead of leaving the initiating terminal attached.
- Do **not** launch or restart persistent remote services from the IDE with `ssh ... nohup ... &` or similar backgrounding patterns at all. This has repeatedly left the local SSH client stuck and hung the user's terminal.
- Do **not** use SSH background-launch commands as a recovery shortcut, even if they appear standard shell-safe.
- For this project, persistent remote service control must use an existing remote supervisor such as `tmux`, `systemctl`, or another already-running session manager, or else stop and ask the user before attempting any new persistent launch method from the IDE.

## Regression Test Harness Phase
- Synced the latest project tree to the QA host `192.168.200.120`
- Rebuilt the QA binary at `/home/krich/src/est-rust-server/target/release/est-server`
- Deployed the rebuilt binary into the active service path `/opt/est-server/est-server`
- Restarted the active QA service via `sudo systemctl restart est-server`
- Verified the QA host is listening on:
  - EST `8443`
  - WebUI `9443`
- Confirmed EST health on the QA host with `cacerts -> 200`
- Confirmed WebUI health on the QA host with `GET /api/status -> 200` over HTTP
- Prepared a demo-backed P12 artifact for regression testing:
  - `demo/rsa-2048-client.p12`
  - password: `changeit`
- Added browser-assisted WebUI regression coverage in `scripts/webui-regression-test.cjs`
- Added category-based regression orchestration in `scripts/run-regression-tests.sh`
- Implemented selectable regression categories:
  - `build`
  - `est`
  - `webui-auth`
  - `webui-config`
  - `webui-users`
  - `webui-rules`
  - `webui-certs`
  - `webui-enrollment`
  - `webui-systemd`
  - `webui-gui`
- Verified representative category execution:
  - `webui-auth`
  - `webui-certs`
  - `webui-gui`

## Current WebUI Certificate Store and Configuration Phase
- The WebUI now exposes a certificate store concept with two sections:
  - Trusted CA
  - Leaf Certificates
- Trusted CA table now displays:
  - Common Name
  - Subject
  - Expires
  - Fingerprint
  - Actions
- Leaf certificate table now displays:
  - Common Name
  - Subject
  - Issuer
  - Expires
  - Fingerprint
  - Assignment
  - Actions
- Trusted CA uploads accept PEM certificates only and persist decoded metadata for browsing.
- Leaf certificate uploads accept P12 bundles only and are validated against the Trusted CA store before import.
- If no trust can be established during P12 import, the WebUI returns the operator message:
  - `The Trusted CA must be loaded first.`
- The configuration view now supports:
  - grouped GUI editing
  - persistence through `POST /api/config`
  - collapsible sections with localStorage-backed collapse state
  - read-only display for derived count fields
- Certificate Store layout was updated from side-by-side panels to a top/bottom stacked layout.
- systemd layout was updated from side-by-side panels to a top/bottom stacked layout.
- Certificate upload file selectors were widened so full filenames are more visible.
- WebUI failure logging was expanded with contextual action metadata for:
  - config save failures
  - certificate upload and delete failures
  - rules save failures
  - pending enrollment approve/reject failures
  - systemd action failures
  - user-management and password-change failures
- The WebUI role model now includes:
  - `super-admin` for user management
  - `admin` for config, rules, certificate, enrollment, and systemd write actions
  - `auditor` for read-only access
- `admin` can now save runtime configuration through the WebUI.
- `auditor` can view status, config, rules, users, certificates, enrollment data, and systemd status, but cannot perform write actions.
- The frontend now exposes read-only behavior for auditors by:
  - showing a read-only badge
  - hiding or disabling write controls
  - keeping view access available across the WebUI
- Leaf certificate assignments are now stored in certificate-store metadata JSON and can be toggled directly in the WebUI with checkbox controls for:
  - EST Server
  - WebUI

## Latest Validation
- Local validation passed:
  - `node --check webui/static/app.js`
  - `cargo check`
  - `cargo fmt --all --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo fmt --all`
  - `cargo check`
  - `cargo test`
  - `cargo clippy --all-targets -- -D warnings`
  - `node --check webui/static/app.js`
- QA deployment completed on `192.168.200.120`:
  - synced workspace to `/home/krich/src/est-rust-server`
  - rebuilt release binary remotely
  - installed binary to `/opt/est-server/est-server`
  - restarted service with `sudo systemctl restart est-server`
- QA regression verification passed:
  - `webui-config`
  - `webui-users`
  - `webui-certs`
  - `webui-systemd`
  - `webui-gui`
  - `bash scripts/run-regression-tests.sh webui-certs`
- Evidence file:
  - `test-results/regression-role-layout-report.md`

## Next Step
Expand regression coverage further only as new WebUI behaviors are added; the current role, layout, and admin-write changes are deployed and validated on the Linux QA host.
