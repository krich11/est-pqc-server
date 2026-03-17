# EST Validation Report

- OpenSSL: OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025)
- Requested EST base URL: https://192.168.200.120:8443
- Effective EST base URL: https://localhost:8443
- EST endpoint base: https://localhost:8443/.well-known/est
- Config path: config.toml
- Remote QA SSH host: krich@192.168.200.120
- Remote project path: /home/krich/src/est-rust-server

## Local Validation Checks

- Config enforces TLS 1.3
- Configured listen port: 8443
- Preferred TLS cipher suite: TLS_AES_256_GCM_SHA384
- ML-KEM support recorded in config: yes
- ML-DSA support recorded in config: no
- Demo CA and required client/server demo artifacts are present
- Demo client/server certificates verify against the generated demo CA

## Transport Validation

- HTTPS endpoint accepts TLS 1.3 connections
- HTTPS endpoint rejects TLS 1.2 connections

## RFC 7030 Success Paths

- `cacerts` returned `200 OK`, correct PKCS#7 media type, and parseable certificate data
- `csrattrs` returned `200 OK`, `application/csrattrs`, and a valid empty ASN.1 sequence
- `simpleenroll` returned `200 OK`, a valid PKCS#7 certs-only response, a certificate matching the CSR public key, and valid stored server-side artifacts
- `simplereenroll` returned `200 OK`, a valid PKCS#7 certs-only response, a certificate matching the CSR public key, and valid stored server-side artifacts
- `serverkeygen` returned `200 OK`, valid multipart PKCS#7 output, a certificate matching the decrypted private key, and valid stored server-side artifacts

## RFC 7030 Deferred `202 Accepted` Paths

- `simpleenroll` supports RFC 7030 deferred processing with `202 Accepted`, `Retry-After`, and successful completion on retry
- `simplereenroll` supports RFC 7030 deferred processing with `202 Accepted`, `Retry-After`, and successful completion on retry
- `serverkeygen` supports RFC 7030 deferred processing with `202 Accepted`, `Retry-After`, and successful completion on retry

## Negative Validation

- Unknown EST endpoint returns `404 Not Found` with plaintext body
- `simpleenroll` rejects invalid `Content-Type` with `415 Unsupported Media Type`
- `simpleenroll` rejects an empty PKCS#10 body with `400 Bad Request`
- `simpleenroll` requires mutual TLS and returns `403 Forbidden` without a client certificate
- `simplereenroll` rejects a CSR whose subject or subjectAltName does not match the current client certificate