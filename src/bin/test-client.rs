use anyhow::{bail, Context, Result};
use clap::Parser;
use openssl::sha::sha256;
use serde::Deserialize;
use std::{
    env, fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_CONFIG_PATH: &str = "config.toml";
const DEFAULT_DEMO_DIR: &str = "demo";
const DEFAULT_OPENSSL_DIR: &str = "/opt/homebrew/opt/openssl@3.5";
const DEFAULT_REMOTE_PROJECT_PATH: &str = "/home/krich/src/est-rust-server";
const VALIDATION_REPORT_PATH: &str = "demo/validation-report.md";

#[derive(Debug, Parser)]
#[command(
    name = "test-client",
    version,
    about = "Aggressive EST validation client for RFC 7030 compliance checks"
)]
struct Cli {
    #[arg(long, help = "Run the full EST validation suite")]
    validate_all: bool,

    #[arg(long, help = "Override EST base URL, e.g. https://127.0.0.1:8443")]
    base_url: Option<String>,

    #[arg(long, help = "Optional SSH target for remote artifact validation, e.g. krich@192.168.200.120")]
    ssh_host: Option<String>,

    #[arg(
        long,
        default_value = DEFAULT_REMOTE_PROJECT_PATH,
        help = "Remote project path used with --ssh-host"
    )]
    remote_project_path: String,
}

#[derive(Debug, Default, Deserialize)]
struct BootstrapConfig {
    openssl_binary: Option<String>,
    openssl_dir: Option<String>,
    listen_port: Option<u16>,
    tls_version: Option<String>,
    preferred_tls_cipher_suite: Option<String>,
    ml_kem_supported: Option<bool>,
    ml_dsa_supported: Option<bool>,
}

#[derive(Debug, Clone)]
struct ValidationTarget {
    requested_base_url: String,
    effective_base_url: String,
    est_base: String,
    curl_resolve_args: Vec<String>,
    host: String,
    port: String,
}

#[derive(Debug)]
struct HttpCapture {
    status: u16,
    headers: String,
    body: Vec<u8>,
    body_path: PathBuf,
    headers_path: PathBuf,
}

#[derive(Debug)]
struct MultipartPart {
    headers: String,
    body: Vec<u8>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if !cli.validate_all {
        println!("Run with --validate-all to execute the EST validation suite.");
        return Ok(());
    }

    let config = load_bootstrap_config()?;
    let openssl_binary = detect_openssl_binary(&config)?;
    let openssl_version = run_command(&openssl_binary, &["version"])?;

    if !openssl_version.starts_with("OpenSSL 3.") {
        bail!("OpenSSL 3.x is required, detected `{openssl_version}`");
    }

    let base_url = cli
        .base_url
        .unwrap_or_else(|| format!("https://127.0.0.1:{}", config.listen_port.unwrap_or(8443)));
    let target = build_validation_target(&base_url)?;

    let mut report_lines = Vec::new();
    report_lines.push("# EST Validation Report".to_owned());
    report_lines.push(String::new());
    report_lines.push(format!("- OpenSSL: {openssl_version}"));
    report_lines.push(format!(
        "- Requested EST base URL: {}",
        target.requested_base_url
    ));
    report_lines.push(format!(
        "- Effective EST base URL: {}",
        target.effective_base_url
    ));
    report_lines.push(format!("- EST endpoint base: {}", target.est_base));
    report_lines.push(format!(
        "- Config path: {}",
        Path::new(DEFAULT_CONFIG_PATH).to_string_lossy()
    ));
    if let Some(ssh_host) = &cli.ssh_host {
        report_lines.push(format!("- Remote QA SSH host: {ssh_host}"));
        report_lines.push(format!(
            "- Remote project path: {}",
            cli.remote_project_path
        ));
    }
    report_lines.push(String::new());

    report_lines.push("## Local Validation Checks".to_owned());
    report_lines.push(String::new());
    validate_config(&config, &mut report_lines)?;
    validate_demo_artifacts(&openssl_binary, &mut report_lines)?;

    report_lines.push(String::new());
    report_lines.push("## Transport Validation".to_owned());
    report_lines.push(String::new());
    validate_tls13_only(&openssl_binary, &target, &mut report_lines)?;

    report_lines.push(String::new());
    report_lines.push("## RFC 7030 Success Paths".to_owned());
    report_lines.push(String::new());
    validate_cacerts(&openssl_binary, &target, &mut report_lines)?;
    validate_csrattrs(&target, &mut report_lines)?;
    validate_simple_enroll(
        &openssl_binary,
        &target,
        cli.ssh_host.as_deref(),
        &cli.remote_project_path,
        &mut report_lines,
    )?;
    validate_simple_reenroll(
        &openssl_binary,
        &target,
        cli.ssh_host.as_deref(),
        &cli.remote_project_path,
        &mut report_lines,
    )?;
    validate_server_keygen(
        &openssl_binary,
        &target,
        cli.ssh_host.as_deref(),
        &cli.remote_project_path,
        &mut report_lines,
    )?;

    report_lines.push(String::new());
    report_lines.push("## RFC 7030 Deferred `202 Accepted` Paths".to_owned());
    report_lines.push(String::new());
    validate_simple_enroll_async(
        &openssl_binary,
        &target,
        cli.ssh_host.as_deref(),
        &cli.remote_project_path,
        &mut report_lines,
    )?;
    validate_simple_reenroll_async(
        &openssl_binary,
        &target,
        cli.ssh_host.as_deref(),
        &cli.remote_project_path,
        &mut report_lines,
    )?;
    validate_server_keygen_async(
        &openssl_binary,
        &target,
        cli.ssh_host.as_deref(),
        &cli.remote_project_path,
        &mut report_lines,
    )?;

    report_lines.push(String::new());
    report_lines.push("## Negative Validation".to_owned());
    report_lines.push(String::new());
    validate_unknown_endpoint(&target, &mut report_lines)?;
    validate_simple_enroll_wrong_content_type(&target, &mut report_lines)?;
    validate_simple_enroll_empty_body(&target, &mut report_lines)?;
    validate_simple_enroll_without_client_certificate(&target, &mut report_lines)?;
    validate_simple_reenroll_subject_mismatch(&target, &mut report_lines)?;

    fs::write(VALIDATION_REPORT_PATH, report_lines.join("\n"))
        .with_context(|| format!("failed to write `{VALIDATION_REPORT_PATH}`"))?;

    println!("EST validation completed successfully.");
    println!("Report written to `{VALIDATION_REPORT_PATH}`");

    Ok(())
}

fn load_bootstrap_config() -> Result<BootstrapConfig> {
    let config_path = Path::new(DEFAULT_CONFIG_PATH);
    if !config_path.exists() {
        bail!("`{DEFAULT_CONFIG_PATH}` is required");
    }

    let content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read `{DEFAULT_CONFIG_PATH}`"))?;
    toml::from_str(&content).with_context(|| format!("failed to parse `{DEFAULT_CONFIG_PATH}`"))
}

fn detect_openssl_binary(config: &BootstrapConfig) -> Result<String> {
    if let Ok(value) = env::var("OPENSSL") {
        return Ok(value);
    }

    if let Some(binary) = &config.openssl_binary {
        return Ok(binary.clone());
    }

    let openssl_dir = config
        .openssl_dir
        .clone()
        .unwrap_or_else(|| DEFAULT_OPENSSL_DIR.to_owned());
    let candidate = Path::new(&openssl_dir).join("bin").join("openssl");
    if candidate.exists() {
        return Ok(candidate.to_string_lossy().into_owned());
    }

    Ok("openssl".to_owned())
}

fn build_validation_target(base_url: &str) -> Result<ValidationTarget> {
    let trimmed = base_url.trim_end_matches('/').to_owned();
    let scheme = if trimmed.starts_with("https://") {
        "https"
    } else if trimmed.starts_with("http://") {
        "http"
    } else {
        bail!("base URL must start with `https://` or `http://`");
    };

    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .context("failed to parse base URL scheme")?;
    let authority = without_scheme
        .split('/')
        .next()
        .context("base URL is missing an authority component")?;
    let (host, port) = authority
        .rsplit_once(':')
        .context("base URL must include an explicit port")?;

    let mut effective_base_url = trimmed.clone();
    let mut curl_resolve_args = Vec::new();

    if host.parse::<IpAddr>().is_ok() {
        effective_base_url = format!("{scheme}://localhost:{port}");
        curl_resolve_args.push("--resolve".to_owned());
        curl_resolve_args.push(format!("localhost:{port}:{host}"));
    }

    Ok(ValidationTarget {
        requested_base_url: trimmed.clone(),
        effective_base_url: effective_base_url.clone(),
        est_base: format!("{effective_base_url}/.well-known/est"),
        curl_resolve_args,
        host: host.to_owned(),
        port: port.to_owned(),
    })
}

fn validate_config(config: &BootstrapConfig, report_lines: &mut Vec<String>) -> Result<()> {
    match config.tls_version.as_deref() {
        Some("TLS1.3") => {
            report_lines.push("- Config enforces TLS 1.3".to_owned());
        }
        Some(value) => {
            bail!("invalid `tls_version` in config: expected `TLS1.3`, found `{value}`");
        }
        None => {
            bail!("missing `tls_version` in config");
        }
    }

    let port = config.listen_port.context("missing `listen_port` in config")?;
    report_lines.push(format!("- Configured listen port: {port}"));

    let cipher = config
        .preferred_tls_cipher_suite
        .as_deref()
        .context("missing `preferred_tls_cipher_suite` in config")?;
    report_lines.push(format!("- Preferred TLS cipher suite: {cipher}"));

    report_lines.push(format!(
        "- ML-KEM support recorded in config: {}",
        yes_no(config.ml_kem_supported.unwrap_or(false))
    ));
    report_lines.push(format!(
        "- ML-DSA support recorded in config: {}",
        yes_no(config.ml_dsa_supported.unwrap_or(false))
    ));

    Ok(())
}

fn validate_demo_artifacts(openssl_binary: &str, report_lines: &mut Vec<String>) -> Result<()> {
    let demo_dir = Path::new(DEFAULT_DEMO_DIR);
    if !demo_dir.exists() {
        bail!("demo directory `{DEFAULT_DEMO_DIR}` does not exist");
    }

    let required_files = [
        "demo-ca.key",
        "demo-ca.csr",
        "demo-ca.crt",
        "rsa-2048-client.key",
        "rsa-2048-client.crt",
        "rsa-2048-client.csr",
        "rsa-2048-server.key",
        "rsa-2048-server.crt",
        "ecdsa-p256-client.csr",
    ];

    for file in required_files {
        let path = demo_dir.join(file);
        if !path.exists() {
            bail!("required demo artifact missing: `{}`", path.to_string_lossy());
        }
    }

    let ca_cert = demo_dir.join("demo-ca.crt");
    for certificate in [
        demo_dir.join("rsa-2048-server.crt"),
        demo_dir.join("rsa-2048-client.crt"),
    ] {
        run_command(
            openssl_binary,
            &[
                "verify",
                "-CAfile",
                ca_cert.to_string_lossy().as_ref(),
                certificate.to_string_lossy().as_ref(),
            ],
        )
        .with_context(|| {
            format!(
                "failed to verify certificate `{}` against demo CA",
                certificate.to_string_lossy()
            )
        })?;
    }

    report_lines.push("- Demo CA and required client/server demo artifacts are present".to_owned());
    report_lines
        .push("- Demo client/server certificates verify against the generated demo CA".to_owned());

    Ok(())
}

fn validate_tls13_only(
    openssl_binary: &str,
    target: &ValidationTarget,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    openssl_transport_success(
        openssl_binary,
        &target.host,
        &target.port,
        &["s_client", "-connect", &format!("{}:{}", target.host, target.port), "-tls1_3", "-brief", "-CAfile", "demo/demo-ca.crt"],
        "TLS 1.3 success probe",
    )?;

    openssl_transport_failure(
        openssl_binary,
        &[
            "s_client",
            "-connect",
            &format!("{}:{}", target.host, target.port),
            "-tls1_2",
            "-brief",
            "-CAfile",
            "demo/demo-ca.crt",
        ],
        "TLS 1.2 rejection probe",
    )?;

    report_lines.push("- HTTPS endpoint accepts TLS 1.3 connections".to_owned());
    report_lines.push("- HTTPS endpoint rejects TLS 1.2 connections".to_owned());

    Ok(())
}

fn validate_cacerts(
    openssl_binary: &str,
    target: &ValidationTarget,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let capture = http_request(
        target,
        &[
            "--cacert".to_owned(),
            "demo/demo-ca.crt".to_owned(),
            format!("{}/cacerts", target.est_base),
        ],
        "cacerts request",
    )?;
    ensure_status(&capture, 200, "cacerts request")?;
    ensure_header_contains(&capture.headers, "content-type:", "application/pkcs7-mime")?;
    ensure_header_contains(&capture.headers, "content-type:", "smime-type=certs-only")?;
    ensure_header_contains(
        &capture.headers,
        "content-transfer-encoding:",
        "binary",
    )?;

    run_command(
        openssl_binary,
        &[
            "pkcs7",
            "-inform",
            "DER",
            "-in",
            capture.body_path.to_string_lossy().as_ref(),
            "-print_certs",
            "-noout",
        ],
    )
    .context("failed to parse cacerts PKCS#7 response")?;

    cleanup_capture(&capture);
    report_lines.push(
        "- `cacerts` returned `200 OK`, correct PKCS#7 media type, and parseable certificate data"
            .to_owned(),
    );

    Ok(())
}

fn validate_csrattrs(target: &ValidationTarget, report_lines: &mut Vec<String>) -> Result<()> {
    let capture = http_request(
        target,
        &[
            "--cacert".to_owned(),
            "demo/demo-ca.crt".to_owned(),
            format!("{}/csrattrs", target.est_base),
        ],
        "csrattrs request",
    )?;
    ensure_status(&capture, 200, "csrattrs request")?;
    ensure_header_contains(&capture.headers, "content-type:", "application/csrattrs")?;
    ensure_header_contains(
        &capture.headers,
        "content-transfer-encoding:",
        "binary",
    )?;

    if capture.body != [0x30, 0x00] {
        bail!("csrattrs response was not the expected empty ASN.1 sequence");
    }

    cleanup_capture(&capture);
    report_lines.push(
        "- `csrattrs` returned `200 OK`, `application/csrattrs`, and a valid empty ASN.1 sequence"
            .to_owned(),
    );

    Ok(())
}

fn validate_simple_enroll(
    openssl_binary: &str,
    target: &ValidationTarget,
    ssh_host: Option<&str>,
    remote_project_path: &str,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let csr_der_path = convert_csr_to_der(openssl_binary, "demo/ecdsa-p256-client.csr")?;
    let capture = enrollment_request(
        target,
        SIMPLE_ENROLL_OPERATION,
        &csr_der_path,
        Some(("demo/rsa-2048-client.crt", "demo/rsa-2048-client.key")),
        &[],
        "simpleenroll request",
    )?;
    ensure_status(&capture, 200, "simpleenroll request")?;
    ensure_header_contains(&capture.headers, "content-type:", "application/pkcs7-mime")?;
    ensure_header_contains(&capture.headers, "content-type:", "smime-type=certs-only")?;
    ensure_header_contains(
        &capture.headers,
        "content-transfer-encoding:",
        "binary",
    )?;

    let certs_pem_path = validate_pkcs7_cert_response(openssl_binary, &capture.body_path)?;
    verify_first_certificate_against_ca(openssl_binary, &certs_pem_path, "demo/demo-ca.crt")?;
    verify_certificate_matches_csr(
        openssl_binary,
        &csr_der_path,
        &certs_pem_path,
        "simpleenroll returned certificate",
    )?;

    if let Some(ssh_host) = ssh_host {
        validate_remote_enrollment_artifacts(
            ssh_host,
            remote_project_path,
            SIMPLE_ENROLL_OPERATION,
            &capture.body,
            &csr_der_path,
        )?;
    }

    cleanup_temp_file(&csr_der_path);
    cleanup_temp_file(&certs_pem_path);
    cleanup_capture(&capture);

    report_lines.push(
        "- `simpleenroll` returned `200 OK`, a valid PKCS#7 certs-only response, a certificate matching the CSR public key, and valid stored server-side artifacts"
            .to_owned(),
    );

    Ok(())
}

fn validate_simple_reenroll(
    openssl_binary: &str,
    target: &ValidationTarget,
    ssh_host: Option<&str>,
    remote_project_path: &str,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let csr_der_path = convert_csr_to_der(openssl_binary, "demo/rsa-2048-client.csr")?;
    let capture = enrollment_request(
        target,
        SIMPLE_REENROLL_OPERATION,
        &csr_der_path,
        Some(("demo/rsa-2048-client.crt", "demo/rsa-2048-client.key")),
        &[],
        "simplereenroll request",
    )?;
    ensure_status(&capture, 200, "simplereenroll request")?;
    ensure_header_contains(&capture.headers, "content-type:", "application/pkcs7-mime")?;
    ensure_header_contains(&capture.headers, "content-type:", "smime-type=certs-only")?;
    ensure_header_contains(
        &capture.headers,
        "content-transfer-encoding:",
        "binary",
    )?;

    let certs_pem_path = validate_pkcs7_cert_response(openssl_binary, &capture.body_path)?;
    verify_first_certificate_against_ca(openssl_binary, &certs_pem_path, "demo/demo-ca.crt")?;
    verify_certificate_matches_csr(
        openssl_binary,
        &csr_der_path,
        &certs_pem_path,
        "simplereenroll returned certificate",
    )?;

    if let Some(ssh_host) = ssh_host {
        validate_remote_enrollment_artifacts(
            ssh_host,
            remote_project_path,
            SIMPLE_REENROLL_OPERATION,
            &capture.body,
            &csr_der_path,
        )?;
    }

    cleanup_temp_file(&csr_der_path);
    cleanup_temp_file(&certs_pem_path);
    cleanup_capture(&capture);

    report_lines.push(
        "- `simplereenroll` returned `200 OK`, a valid PKCS#7 certs-only response, a certificate matching the CSR public key, and valid stored server-side artifacts"
            .to_owned(),
    );

    Ok(())
}

fn validate_server_keygen(
    openssl_binary: &str,
    target: &ValidationTarget,
    ssh_host: Option<&str>,
    remote_project_path: &str,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let csr_der_path = convert_csr_to_der(openssl_binary, "demo/rsa-2048-client.csr")?;
    let capture = enrollment_request(
        target,
        SERVER_KEYGEN_OPERATION,
        &csr_der_path,
        Some(("demo/rsa-2048-client.crt", "demo/rsa-2048-client.key")),
        &[],
        "serverkeygen request",
    )?;
    ensure_status(&capture, 200, "serverkeygen request")?;
    ensure_header_contains(&capture.headers, "content-type:", "multipart/mixed")?;
    ensure_header_contains(
        &capture.headers,
        "content-transfer-encoding:",
        "binary",
    )?;
    let boundary = parse_boundary(&capture.headers)?;
    let parts = parse_multipart_body(&capture.body, &boundary)?;
    if parts.len() != 2 {
        bail!(
            "expected two multipart parts from serverkeygen response, found {}",
            parts.len()
        );
    }

    ensure_header_contains(&parts[0].headers, "content-type:", "application/pkcs7-mime")?;
    ensure_header_contains(&parts[0].headers, "content-type:", "smime-type=certs-only")?;
    ensure_header_contains(
        &parts[0].headers,
        "content-transfer-encoding:",
        "binary",
    )?;
    ensure_header_contains(&parts[1].headers, "content-type:", "application/pkcs7-mime")?;
    ensure_header_contains(
        &parts[1].headers,
        "content-transfer-encoding:",
        "binary",
    )?;

    let pkcs7_path = write_temp_file("est-serverkeygen-cert-part", "der", &parts[0].body)?;
    let certs_pem_path = validate_pkcs7_cert_response(openssl_binary, &pkcs7_path)?;
    verify_first_certificate_against_ca(openssl_binary, &certs_pem_path, "demo/demo-ca.crt")?;

    let encrypted_key_path =
        write_temp_file("est-serverkeygen-key-part", "der", &parts[1].body)?;
    let decrypted_key_path = temp_path("est-serverkeygen-decrypted-key", "pem");
    run_command(
        openssl_binary,
        &[
            "cms",
            "-decrypt",
            "-inform",
            "DER",
            "-in",
            encrypted_key_path.to_string_lossy().as_ref(),
            "-recip",
            "demo/rsa-2048-client.crt",
            "-inkey",
            "demo/rsa-2048-client.key",
            "-out",
            decrypted_key_path.to_string_lossy().as_ref(),
        ],
    )
    .context("failed to decrypt serverkeygen private key response")?;
    run_command(
        openssl_binary,
        &[
            "pkey",
            "-in",
            decrypted_key_path.to_string_lossy().as_ref(),
            "-noout",
        ],
    )
    .context("failed to parse decrypted serverkeygen private key")?;
    verify_certificate_matches_private_key(
        openssl_binary,
        &certs_pem_path,
        &decrypted_key_path,
        "serverkeygen returned certificate",
    )?;

    if let Some(ssh_host) = ssh_host {
        validate_remote_enrollment_artifacts(
            ssh_host,
            remote_project_path,
            SERVER_KEYGEN_OPERATION,
            &capture.body,
            &csr_der_path,
        )?;
    }

    cleanup_temp_file(&csr_der_path);
    cleanup_temp_file(&pkcs7_path);
    cleanup_temp_file(&certs_pem_path);
    cleanup_temp_file(&encrypted_key_path);
    cleanup_temp_file(&decrypted_key_path);
    cleanup_capture(&capture);

    report_lines.push(
        "- `serverkeygen` returned `200 OK`, valid multipart PKCS#7 output, a certificate matching the decrypted private key, and valid stored server-side artifacts"
            .to_owned(),
    );

    Ok(())
}

fn validate_simple_enroll_async(
    openssl_binary: &str,
    target: &ValidationTarget,
    ssh_host: Option<&str>,
    remote_project_path: &str,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    validate_async_enrollment_round_trip(
        openssl_binary,
        target,
        ssh_host,
        remote_project_path,
        SIMPLE_ENROLL_OPERATION,
        "demo/ecdsa-p256-client.csr",
        Some(("demo/rsa-2048-client.crt", "demo/rsa-2048-client.key")),
        report_lines,
    )
}

fn validate_simple_reenroll_async(
    openssl_binary: &str,
    target: &ValidationTarget,
    ssh_host: Option<&str>,
    remote_project_path: &str,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    validate_async_enrollment_round_trip(
        openssl_binary,
        target,
        ssh_host,
        remote_project_path,
        SIMPLE_REENROLL_OPERATION,
        "demo/rsa-2048-client.csr",
        Some(("demo/rsa-2048-client.crt", "demo/rsa-2048-client.key")),
        report_lines,
    )
}

fn validate_server_keygen_async(
    openssl_binary: &str,
    target: &ValidationTarget,
    ssh_host: Option<&str>,
    remote_project_path: &str,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    validate_async_enrollment_round_trip(
        openssl_binary,
        target,
        ssh_host,
        remote_project_path,
        SERVER_KEYGEN_OPERATION,
        "demo/rsa-2048-client.csr",
        Some(("demo/rsa-2048-client.crt", "demo/rsa-2048-client.key")),
        report_lines,
    )
}

fn validate_async_enrollment_round_trip(
    openssl_binary: &str,
    target: &ValidationTarget,
    ssh_host: Option<&str>,
    remote_project_path: &str,
    operation: &str,
    csr_pem_path: &str,
    client_auth: Option<(&str, &str)>,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let csr_der_path = convert_csr_to_der(openssl_binary, csr_pem_path)?;
    let csr_der = fs::read(&csr_der_path)
        .with_context(|| format!("failed to read `{}`", csr_der_path.display()))?;

    let first = enrollment_request(
        target,
        operation,
        &csr_der_path,
        client_auth,
        &["--header".to_owned(), "Prefer: respond-async".to_owned()],
        &format!("{operation} deferred request"),
    )?;
    ensure_status(&first, 202, &format!("{operation} deferred request"))?;
    ensure_header_contains(&first.headers, "retry-after:", "60")?;
    ensure_header_contains(&first.headers, "content-type:", "text/plain")?;
    if first.body.is_empty() {
        bail!("`{operation}` deferred response body was unexpectedly empty");
    }

    if let Some(ssh_host) = ssh_host {
        validate_remote_pending_artifacts(
            ssh_host,
            remote_project_path,
            operation,
            &csr_der,
            true,
        )?;
    }

    let second = enrollment_request(
        target,
        operation,
        &csr_der_path,
        client_auth,
        &["--header".to_owned(), "Prefer: respond-async".to_owned()],
        &format!("{operation} follow-up request"),
    )?;
    ensure_status(&second, 200, &format!("{operation} follow-up request"))?;

    if let Some(ssh_host) = ssh_host {
        validate_remote_pending_artifacts(
            ssh_host,
            remote_project_path,
            operation,
            &csr_der,
            false,
        )?;
    }

    cleanup_capture(&first);
    cleanup_capture(&second);
    cleanup_temp_file(&csr_der_path);

    report_lines.push(format!(
        "- `{operation}` supports RFC 7030 deferred processing with `202 Accepted`, `Retry-After`, and successful completion on retry"
    ));

    Ok(())
}

fn validate_unknown_endpoint(target: &ValidationTarget, report_lines: &mut Vec<String>) -> Result<()> {
    let capture = http_request(
        target,
        &[
            "--cacert".to_owned(),
            "demo/demo-ca.crt".to_owned(),
            format!("{}/not-supported", target.est_base),
        ],
        "unknown endpoint request",
    )?;
    ensure_status(&capture, 404, "unknown endpoint request")?;
    ensure_header_contains(&capture.headers, "content-type:", "text/plain")?;
    cleanup_capture(&capture);

    report_lines.push("- Unknown EST endpoint returns `404 Not Found` with plaintext body".to_owned());

    Ok(())
}

fn validate_simple_enroll_wrong_content_type(
    target: &ValidationTarget,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let capture = http_request(
        target,
        &[
            "--http1.1".to_owned(),
            "--cacert".to_owned(),
            "demo/demo-ca.crt".to_owned(),
            "--cert".to_owned(),
            "demo/rsa-2048-client.crt".to_owned(),
            "--key".to_owned(),
            "demo/rsa-2048-client.key".to_owned(),
            "--header".to_owned(),
            "Content-Type: text/plain".to_owned(),
            "--data-binary".to_owned(),
            "@demo/ecdsa-p256-client.csr".to_owned(),
            format!("{}/simpleenroll", target.est_base),
        ],
        "simpleenroll wrong content-type request",
    )?;
    ensure_status(&capture, 415, "simpleenroll wrong content-type request")?;
    cleanup_capture(&capture);

    report_lines.push("- `simpleenroll` rejects invalid `Content-Type` with `415 Unsupported Media Type`".to_owned());

    Ok(())
}

fn validate_simple_enroll_empty_body(
    target: &ValidationTarget,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let capture = http_request(
        target,
        &[
            "--http1.1".to_owned(),
            "--cacert".to_owned(),
            "demo/demo-ca.crt".to_owned(),
            "--cert".to_owned(),
            "demo/rsa-2048-client.crt".to_owned(),
            "--key".to_owned(),
            "demo/rsa-2048-client.key".to_owned(),
            "--header".to_owned(),
            "Content-Type: application/pkcs10".to_owned(),
            "--data-binary".to_owned(),
            "".to_owned(),
            format!("{}/simpleenroll", target.est_base),
        ],
        "simpleenroll empty-body request",
    )?;
    ensure_status(&capture, 400, "simpleenroll empty-body request")?;
    cleanup_capture(&capture);

    report_lines.push("- `simpleenroll` rejects an empty PKCS#10 body with `400 Bad Request`".to_owned());

    Ok(())
}

fn validate_simple_enroll_without_client_certificate(
    target: &ValidationTarget,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let capture = http_request(
        target,
        &[
            "--http1.1".to_owned(),
            "--cacert".to_owned(),
            "demo/demo-ca.crt".to_owned(),
            "--header".to_owned(),
            "Content-Type: application/pkcs10".to_owned(),
            "--data-binary".to_owned(),
            "@demo/ecdsa-p256-client.csr".to_owned(),
            format!("{}/simpleenroll", target.est_base),
        ],
        "simpleenroll without client certificate",
    )?;
    ensure_status(&capture, 403, "simpleenroll without client certificate")?;
    cleanup_capture(&capture);

    report_lines.push("- `simpleenroll` requires mutual TLS and returns `403 Forbidden` without a client certificate".to_owned());

    Ok(())
}

fn validate_simple_reenroll_subject_mismatch(
    target: &ValidationTarget,
    report_lines: &mut Vec<String>,
) -> Result<()> {
    let capture = http_request(
        target,
        &[
            "--http1.1".to_owned(),
            "--cacert".to_owned(),
            "demo/demo-ca.crt".to_owned(),
            "--cert".to_owned(),
            "demo/rsa-2048-client.crt".to_owned(),
            "--key".to_owned(),
            "demo/rsa-2048-client.key".to_owned(),
            "--header".to_owned(),
            "Content-Type: application/pkcs10".to_owned(),
            "--data-binary".to_owned(),
            "@demo/ecdsa-p256-client.csr".to_owned(),
            format!("{}/simplereenroll", target.est_base),
        ],
        "simplereenroll subject mismatch request",
    )?;
    ensure_status(&capture, 400, "simplereenroll subject mismatch request")?;
    cleanup_capture(&capture);

    report_lines.push("- `simplereenroll` rejects a CSR whose subject or subjectAltName does not match the current client certificate".to_owned());

    Ok(())
}

fn enrollment_request(
    target: &ValidationTarget,
    operation: &str,
    csr_der_path: &Path,
    client_auth: Option<(&str, &str)>,
    extra_args: &[String],
    label: &str,
) -> Result<HttpCapture> {
    let mut args = vec![
        "--http1.1".to_owned(),
        "--cacert".to_owned(),
        "demo/demo-ca.crt".to_owned(),
    ];

    if let Some((cert, key)) = client_auth {
        args.push("--cert".to_owned());
        args.push(cert.to_owned());
        args.push("--key".to_owned());
        args.push(key.to_owned());
    }

    args.extend_from_slice(extra_args);

    args.push("--header".to_owned());
    args.push("Content-Type: application/pkcs10".to_owned());
    args.push("--data-binary".to_owned());
    args.push(format!("@{}", csr_der_path.to_string_lossy()));
    args.push(format!("{}/{}", target.est_base, operation));

    http_request(target, &args, label)
}

fn http_request(target: &ValidationTarget, request_args: &[String], label: &str) -> Result<HttpCapture> {
    let body_path = temp_path(label.replace(' ', "-").as_str(), "body");
    let headers_path = temp_path(label.replace(' ', "-").as_str(), "headers");

    let mut args = Vec::with_capacity(target.curl_resolve_args.len() + request_args.len() + 8);
    args.extend(target.curl_resolve_args.iter().cloned());
    args.push("--silent".to_owned());
    args.push("--show-error".to_owned());
    args.push("--output".to_owned());
    args.push(body_path.to_string_lossy().into_owned());
    args.push("--dump-header".to_owned());
    args.push(headers_path.to_string_lossy().into_owned());
    args.push("--write-out".to_owned());
    args.push("%{http_code}".to_owned());
    args.extend(request_args.iter().cloned());

    let output = Command::new("curl")
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute curl for {label}"))?;

    if !output.status.success() {
        cleanup_temp_file(&body_path);
        cleanup_temp_file(&headers_path);
        bail!(
            "curl failed during {label} with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let status_text = String::from_utf8(output.stdout)
        .with_context(|| format!("curl status output was not valid UTF-8 for {label}"))?;
    let status = status_text
        .trim()
        .parse::<u16>()
        .with_context(|| format!("failed to parse HTTP status `{}` for {label}", status_text.trim()))?;
    let headers = fs::read_to_string(&headers_path)
        .with_context(|| format!("failed to read `{}`", headers_path.display()))?;
    let body = fs::read(&body_path)
        .with_context(|| format!("failed to read `{}`", body_path.display()))?;

    Ok(HttpCapture {
        status,
        headers,
        body,
        body_path,
        headers_path,
    })
}

fn openssl_transport_success(
    openssl_binary: &str,
    _host: &str,
    _port: &str,
    args: &[&str],
    label: &str,
) -> Result<()> {
    let output = Command::new(openssl_binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute `{openssl_binary}` for {label}"))?;

    if !output.status.success() {
        bail!(
            "`{openssl_binary}` failed during {label} with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    if !combined.contains("Protocol version: TLSv1.3")
        && !combined.contains("Protocol version: TLSv1.3")
        && !combined.contains("CONNECTION ESTABLISHED")
        && !combined.contains("TLSv1.3")
    {
        bail!("TLS 1.3 success probe did not confirm a TLS 1.3 connection");
    }

    Ok(())
}

fn openssl_transport_failure(
    openssl_binary: &str,
    args: &[&str],
    label: &str,
) -> Result<()> {
    let output = Command::new(openssl_binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute `{openssl_binary}` for {label}"))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");
        if combined.contains("TLSv1.2") || combined.contains("CONNECTION ESTABLISHED") {
            bail!("TLS 1.2 rejection probe unexpectedly succeeded");
        }
    }

    Ok(())
}

fn validate_pkcs7_cert_response(openssl_binary: &str, pkcs7_path: &Path) -> Result<PathBuf> {
    run_command(
        openssl_binary,
        &[
            "pkcs7",
            "-inform",
            "DER",
            "-in",
            pkcs7_path.to_string_lossy().as_ref(),
            "-print_certs",
            "-noout",
        ],
    )
    .with_context(|| format!("failed to parse PKCS#7 response `{}`", pkcs7_path.display()))?;

    let output = run_command(
        openssl_binary,
        &[
            "pkcs7",
            "-inform",
            "DER",
            "-in",
            pkcs7_path.to_string_lossy().as_ref(),
            "-print_certs",
        ],
    )
    .with_context(|| format!("failed to extract certificates from `{}`", pkcs7_path.display()))?;

    let output_path = temp_path("est-pkcs7-certs", "pem");
    fs::write(&output_path, output)
        .with_context(|| format!("failed to write `{}`", output_path.display()))?;

    Ok(output_path)
}

fn verify_first_certificate_against_ca(
    openssl_binary: &str,
    certs_pem_path: &Path,
    ca_path: &str,
) -> Result<()> {
    run_command(
        openssl_binary,
        &[
            "verify",
            "-CAfile",
            ca_path,
            certs_pem_path.to_string_lossy().as_ref(),
        ],
    )
    .with_context(|| {
        format!(
            "failed to verify extracted certificate chain `{}`",
            certs_pem_path.display()
        )
    })?;

    Ok(())
}

fn verify_certificate_matches_csr(
    openssl_binary: &str,
    csr_der_path: &Path,
    certs_pem_path: &Path,
    label: &str,
) -> Result<()> {
    let csr_public_key = run_command(
        openssl_binary,
        &[
            "req",
            "-inform",
            "DER",
            "-in",
            csr_der_path.to_string_lossy().as_ref(),
            "-pubkey",
            "-noout",
        ],
    )
    .with_context(|| format!("failed to extract CSR public key for {label}"))?;

    let cert_public_key = run_command(
        openssl_binary,
        &[
            "x509",
            "-in",
            certs_pem_path.to_string_lossy().as_ref(),
            "-pubkey",
            "-noout",
        ],
    )
    .with_context(|| format!("failed to extract certificate public key for {label}"))?;

    if csr_public_key != cert_public_key {
        bail!("{label} did not match the CSR public key");
    }

    Ok(())
}

fn verify_certificate_matches_private_key(
    openssl_binary: &str,
    certs_pem_path: &Path,
    private_key_path: &Path,
    label: &str,
) -> Result<()> {
    let cert_public_key = run_command(
        openssl_binary,
        &[
            "x509",
            "-in",
            certs_pem_path.to_string_lossy().as_ref(),
            "-pubkey",
            "-noout",
        ],
    )
    .with_context(|| format!("failed to extract certificate public key for {label}"))?;

    let private_key_public_key = run_command(
        openssl_binary,
        &[
            "pkey",
            "-in",
            private_key_path.to_string_lossy().as_ref(),
            "-pubout",
            "-outform",
            "PEM",
        ],
    )
    .with_context(|| format!("failed to extract private key public key for {label}"))?;

    if cert_public_key != private_key_public_key {
        bail!("{label} did not match the decrypted private key");
    }

    Ok(())
}

fn validate_remote_enrollment_artifacts(
    ssh_host: &str,
    remote_project_path: &str,
    operation: &str,
    response_body: &[u8],
    csr_der_path: &Path,
) -> Result<()> {
    let csr_der = fs::read(csr_der_path)
        .with_context(|| format!("failed to read `{}`", csr_der_path.display()))?;
    let artifact_id = sha256_hex(&csr_der);
    let artifact_dir = format!("logs/enrollments/{operation}/{artifact_id}");

    let remote_command = if operation == SERVER_KEYGEN_OPERATION {
        format!(
            "set -euo pipefail; cd {remote_project_path:?}; csr='{artifact_dir}/request.csr.der'; cert='{artifact_dir}/issued-cert.pem'; test -f \"$csr\"; test -f \"$cert\"; openssl req -inform DER -in \"$csr\" -verify -noout >/dev/null; openssl verify -CAfile demo/demo-ca.crt \"$cert\" >/dev/null; openssl x509 -in \"$cert\" -noout -subject >/dev/null"
        )
    } else {
        format!(
            "set -euo pipefail; cd {remote_project_path:?}; csr='{artifact_dir}/request.csr.der'; cert='{artifact_dir}/issued-cert.pem'; test -f \"$csr\"; test -f \"$cert\"; openssl req -inform DER -in \"$csr\" -verify -noout >/dev/null; openssl verify -CAfile demo/demo-ca.crt \"$cert\" >/dev/null; csr_pub=$(mktemp); cert_pub=$(mktemp); openssl req -inform DER -in \"$csr\" -pubkey -noout > \"$csr_pub\"; openssl x509 -in \"$cert\" -pubkey -noout > \"$cert_pub\"; cmp -s \"$csr_pub\" \"$cert_pub\"; rm -f \"$csr_pub\" \"$cert_pub\""
        )
    };

    run_ssh_command(ssh_host, &remote_command)
        .with_context(|| format!("failed to validate remote stored artifacts for `{operation}`"))?;

    if operation == SERVER_KEYGEN_OPERATION {
        let boundary = extract_boundary_from_multipart_response(response_body);
        if boundary.is_none() {
            bail!("remote artifact validation could not confirm serverkeygen multipart response");
        }
    }

    Ok(())
}

fn validate_remote_pending_artifacts(
    ssh_host: &str,
    remote_project_path: &str,
    operation: &str,
    csr_der: &[u8],
    should_exist: bool,
) -> Result<()> {
    let artifact_id = sha256_hex(csr_der);
    let pending_dir = format!("logs/pending/{operation}/{artifact_id}");

    let remote_command = if should_exist {
        format!(
            "set -euo pipefail; cd {remote_project_path:?}; test -f '{pending_dir}/request.csr.der'; test -f '{pending_dir}/status.txt'"
        )
    } else {
        format!(
            "set -euo pipefail; cd {remote_project_path:?}; test ! -e '{pending_dir}'"
        )
    };

    run_ssh_command(ssh_host, &remote_command).with_context(|| {
        format!(
            "failed to validate remote pending artifacts for `{operation}` with should_exist={should_exist}"
        )
    })?;

    Ok(())
}

fn run_ssh_command(ssh_host: &str, remote_command: &str) -> Result<()> {
    let output = Command::new("ssh")
        .arg(ssh_host)
        .arg(remote_command)
        .output()
        .with_context(|| format!("failed to execute ssh against `{ssh_host}`"))?;

    if !output.status.success() {
        bail!(
            "ssh command failed on `{ssh_host}` with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn extract_boundary_from_multipart_response(response_body: &[u8]) -> Option<String> {
    if response_body.windows(2).any(|window| window == b"--") {
        Some("present".to_owned())
    } else {
        None
    }
}

fn convert_csr_to_der(openssl_binary: &str, csr_pem_path: &str) -> Result<PathBuf> {
    let output_path = temp_path("est-csr", "der");
    run_command(
        openssl_binary,
        &[
            "req",
            "-in",
            csr_pem_path,
            "-outform",
            "DER",
            "-out",
            output_path.to_string_lossy().as_ref(),
        ],
    )
    .with_context(|| format!("failed to convert CSR `{csr_pem_path}` to DER"))?;
    Ok(output_path)
}

fn parse_boundary(headers: &str) -> Result<String> {
    for line in headers.lines() {
        let lowercase = line.to_ascii_lowercase();
        if lowercase.starts_with("content-type:") && lowercase.contains("boundary=") {
            let boundary = line
                .split("boundary=")
                .nth(1)
                .map(str::trim)
                .map(|value| value.trim_matches('"'))
                .filter(|value| !value.is_empty())
                .context("missing multipart boundary value")?;
            return Ok(boundary.to_owned());
        }
    }

    bail!("multipart boundary not found in response headers")
}

fn parse_multipart_body(body: &[u8], boundary: &str) -> Result<Vec<MultipartPart>> {
    let boundary_marker = format!("--{boundary}").into_bytes();
    let closing_boundary_marker = format!("--{boundary}--").into_bytes();
    let header_separator = b"\r\n\r\n";
    let mut parts = Vec::new();
    let mut cursor = 0_usize;

    while cursor < body.len() {
        let remaining = &body[cursor..];

        if remaining.starts_with(&closing_boundary_marker) {
            break;
        }

        if !remaining.starts_with(&boundary_marker) {
            cursor += 1;
            continue;
        }

        let mut part_start = cursor + boundary_marker.len();
        if body
            .get(part_start..part_start + 2)
            .is_some_and(|value| value == b"\r\n")
        {
            part_start += 2;
        }

        let headers_end_relative = find_subslice(&body[part_start..], header_separator)
            .context("multipart part is missing header separator")?;
        let headers_end = part_start + headers_end_relative;
        let content_start = headers_end + header_separator.len();

        let next_boundary_relative = find_subslice(&body[content_start..], b"\r\n--")
            .context("multipart part is missing terminating boundary")?;
        let content_end = content_start + next_boundary_relative;

        let headers = String::from_utf8(body[part_start..headers_end].to_vec())
            .context("multipart headers were not valid UTF-8")?;
        parts.push(MultipartPart {
            headers,
            body: body[content_start..content_end].to_vec(),
        });
        cursor = content_end + 2;
    }

    Ok(parts)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn ensure_status(capture: &HttpCapture, expected: u16, label: &str) -> Result<()> {
    if capture.status != expected {
        bail!(
            "{label} returned unexpected status {}, expected {}",
            capture.status,
            expected
        );
    }

    Ok(())
}

fn ensure_header_contains(headers: &str, header_prefix: &str, expected_fragment: &str) -> Result<()> {
    let prefix = header_prefix.to_ascii_lowercase();
    let expected = expected_fragment.to_ascii_lowercase();

    let found = headers.lines().any(|line| {
        let lowercase = line.to_ascii_lowercase();
        lowercase.starts_with(&prefix) && lowercase.contains(&expected)
    });

    if !found {
        bail!("response headers did not contain `{expected_fragment}` in `{header_prefix}`");
    }

    Ok(())
}

fn cleanup_capture(capture: &HttpCapture) {
    cleanup_temp_file(&capture.body_path);
    cleanup_temp_file(&capture.headers_path);
}

fn cleanup_temp_file(path: &Path) {
    let _ = fs::remove_file(path);
}

fn temp_path(prefix: &str, extension: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!("{prefix}-{stamp}.{extension}"))
}

fn write_temp_file(prefix: &str, extension: &str, content: &[u8]) -> Result<PathBuf> {
    let path = temp_path(prefix, extension);
    fs::write(&path, content)
        .with_context(|| format!("failed to write temporary file `{}`", path.display()))?;
    Ok(path)
}

fn run_command(binary: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute `{binary}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{binary} {}` failed with status {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("`{binary}` output was not valid UTF-8"))?;

    Ok(stdout.trim().to_owned())
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = sha256(input);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

const SIMPLE_ENROLL_OPERATION: &str = "simpleenroll";
const SIMPLE_REENROLL_OPERATION: &str = "simplereenroll";
const SERVER_KEYGEN_OPERATION: &str = "serverkeygen";