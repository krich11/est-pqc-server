use crate::est;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use openssl::{
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::Id as PKeyId,
    x509::{X509NameRef, X509},
};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub const CERTIFICATE_STORE_ROOT: &str = "logs/certificate-store";

#[derive(Debug, Deserialize)]
pub struct UploadTrustedCaRequest {
    pub filename: String,
    pub content_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadLeafCertificateRequest {
    pub filename: String,
    pub password: String,
    pub content_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub fingerprint: String,
    pub original_filename: String,
    #[serde(default = "default_common_name")]
    pub common_name: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    #[serde(default)]
    pub assigned_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedCertificate {
    #[serde(default = "default_common_name")]
    pub common_name: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub san_dns: Vec<String>,
    pub san_email: Vec<String>,
    pub key_algorithm: String,
    pub key_bits: u32,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDetail {
    pub fingerprint: String,
    pub original_filename: String,
    pub leaf: DecodedCertificate,
    pub chain: Vec<DecodedCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCaMetadata {
    original_filename: String,
    certificate: DecodedCertificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredLeafMetadata {
    original_filename: String,
    leaf: DecodedCertificate,
    chain: Vec<DecodedCertificate>,
    #[serde(default)]
    assigned_services: Vec<String>,
}

pub fn certificate_store_root() -> PathBuf {
    PathBuf::from(CERTIFICATE_STORE_ROOT)
}

pub fn initialize_certificate_store(root: &Path) -> Result<()> {
    fs::create_dir_all(trusted_ca_dir(root)).with_context(|| {
        format!(
            "failed to create trusted CA store directory `{}`",
            trusted_ca_dir(root).display()
        )
    })?;
    fs::create_dir_all(leaf_dir(root)).with_context(|| {
        format!(
            "failed to create leaf certificate store directory `{}`",
            leaf_dir(root).display()
        )
    })?;
    fs::create_dir_all(verification_log_dir(root)).with_context(|| {
        format!(
            "failed to create certificate verification log directory `{}`",
            verification_log_dir(root).display()
        )
    })?;
    Ok(())
}

pub fn list_trusted_ca(root: &Path) -> Result<Vec<CertificateSummary>> {
    let mut entries = load_store_metadata::<StoredCaMetadata>(&trusted_ca_dir(root), "json")?
        .into_iter()
        .map(|(fingerprint, metadata)| CertificateSummary {
            fingerprint,
            original_filename: metadata.original_filename,
            common_name: metadata.certificate.common_name,
            subject: metadata.certificate.subject,
            issuer: metadata.certificate.issuer,
            not_before: metadata.certificate.not_before,
            not_after: metadata.certificate.not_after,
            assigned_services: Vec::new(),
        })
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });

    Ok(entries)
}

pub fn upload_trusted_ca(
    root: &Path,
    request: UploadTrustedCaRequest,
) -> Result<CertificateSummary> {
    initialize_certificate_store(root)?;

    let decoded = BASE64_STANDARD
        .decode(request.content_base64.as_bytes())
        .context("trusted CA content was not valid base64")?;
    let certificates = X509::stack_from_pem(&decoded)
        .context("trusted CA upload must be a PEM encoded certificate")?;

    let certificate = match certificates.as_slice() {
        [] => bail!("trusted CA upload did not contain a PEM certificate"),
        [certificate] => certificate,
        _ => bail!("trusted CA upload must contain exactly one PEM certificate"),
    };

    let certificate_pem = certificate
        .to_pem()
        .context("failed to serialize trusted CA certificate")?;
    let certificate_detail = decode_certificate(certificate)?;
    let fingerprint = certificate_detail.fingerprint_sha256.clone();

    fs::write(trusted_ca_pem_path(root, &fingerprint), certificate_pem).with_context(|| {
        format!(
            "failed to write trusted CA certificate `{}`",
            trusted_ca_pem_path(root, &fingerprint).display()
        )
    })?;

    let metadata = StoredCaMetadata {
        original_filename: request.filename,
        certificate: certificate_detail.clone(),
    };
    write_json_file(&trusted_ca_metadata_path(root, &fingerprint), &metadata)?;

    Ok(CertificateSummary {
        fingerprint,
        original_filename: metadata.original_filename,
        common_name: certificate_detail.common_name,
        subject: certificate_detail.subject,
        issuer: certificate_detail.issuer,
        not_before: certificate_detail.not_before,
        not_after: certificate_detail.not_after,
        assigned_services: Vec::new(),
    })
}

pub fn get_trusted_ca(root: &Path, fingerprint: &str) -> Result<CertificateDetail> {
    let metadata: StoredCaMetadata = read_json_file(&trusted_ca_metadata_path(root, fingerprint))?;
    Ok(CertificateDetail {
        fingerprint: fingerprint.to_owned(),
        original_filename: metadata.original_filename,
        leaf: metadata.certificate,
        chain: Vec::new(),
    })
}

pub fn delete_trusted_ca(root: &Path, fingerprint: &str) -> Result<()> {
    delete_if_exists(&trusted_ca_pem_path(root, fingerprint))?;
    delete_if_exists(&trusted_ca_metadata_path(root, fingerprint))?;
    Ok(())
}

pub fn list_leaf_certificates(root: &Path) -> Result<Vec<CertificateSummary>> {
    let mut entries = load_store_metadata::<StoredLeafMetadata>(&leaf_dir(root), "json")?
        .into_iter()
        .map(|(fingerprint, metadata)| {
            Ok(CertificateSummary {
                fingerprint,
                original_filename: metadata.original_filename,
                common_name: metadata.leaf.common_name,
                subject: metadata.leaf.subject,
                issuer: metadata.leaf.issuer,
                not_before: metadata.leaf.not_before,
                not_after: metadata.leaf.not_after,
                assigned_services: normalize_assigned_services(&metadata.assigned_services)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    entries.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });

    Ok(entries)
}

pub fn upload_leaf_certificate(
    root: &Path,
    request: UploadLeafCertificateRequest,
    openssl_binary: &str,
    openssl_providers: &[String],
) -> Result<CertificateSummary> {
    initialize_certificate_store(root)?;

    let decoded = BASE64_STANDARD
        .decode(request.content_base64.as_bytes())
        .context("leaf certificate content was not valid base64")?;
    let pkcs12 =
        Pkcs12::from_der(&decoded).context("leaf certificate upload must be a P12 file")?;
    let parsed = pkcs12
        .parse2(&request.password)
        .context("failed to parse P12 file with the supplied password")?;

    let leaf_certificate = parsed
        .cert
        .ok_or_else(|| anyhow!("P12 file did not contain a leaf certificate"))?;
    let chain_certificates = parsed
        .ca
        .map(|stack| stack.into_iter().collect::<Vec<_>>())
        .unwrap_or_default();
    let trust_error_message = missing_trusted_ca_message(&leaf_certificate)?;

    if list_trusted_ca(root)?.is_empty() {
        bail!(trust_error_message)
    }

    validate_leaf_certificate_trust(
        root,
        openssl_binary,
        openssl_providers,
        &leaf_certificate,
        &chain_certificates,
    )
    .map_err(|error| anyhow!("{trust_error_message} Details: {error}"))?;

    let leaf_detail = decode_certificate(&leaf_certificate)?;
    let fingerprint = leaf_detail.fingerprint_sha256.clone();
    let chain_details = chain_certificates
        .iter()
        .map(decode_certificate)
        .collect::<Result<Vec<_>>>()?;

    fs::write(leaf_p12_path(root, &fingerprint), decoded).with_context(|| {
        format!(
            "failed to write leaf certificate `{}`",
            leaf_p12_path(root, &fingerprint).display()
        )
    })?;
    fs::write(
        leaf_certificate_pem_path(root, &fingerprint),
        leaf_certificate
            .to_pem()
            .context("failed to serialize extracted leaf certificate")?,
    )
    .with_context(|| {
        format!(
            "failed to write extracted leaf certificate `{}`",
            leaf_certificate_pem_path(root, &fingerprint).display()
        )
    })?;

    let chain_pem = chain_certificates
        .iter()
        .map(|certificate| certificate.to_pem())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to serialize extracted leaf certificate chain")?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    fs::write(leaf_chain_pem_path(root, &fingerprint), chain_pem).with_context(|| {
        format!(
            "failed to write extracted certificate chain `{}`",
            leaf_chain_pem_path(root, &fingerprint).display()
        )
    })?;

    let metadata = StoredLeafMetadata {
        original_filename: request.filename,
        leaf: leaf_detail.clone(),
        chain: chain_details,
        assigned_services: Vec::new(),
    };
    write_json_file(&leaf_metadata_path(root, &fingerprint), &metadata)?;

    Ok(CertificateSummary {
        fingerprint,
        original_filename: metadata.original_filename,
        common_name: leaf_detail.common_name,
        subject: leaf_detail.subject,
        issuer: leaf_detail.issuer,
        not_before: leaf_detail.not_before,
        not_after: leaf_detail.not_after,
        assigned_services: Vec::new(),
    })
}

pub fn get_leaf_certificate(root: &Path, fingerprint: &str) -> Result<CertificateDetail> {
    let metadata: StoredLeafMetadata = read_json_file(&leaf_metadata_path(root, fingerprint))?;
    Ok(CertificateDetail {
        fingerprint: fingerprint.to_owned(),
        original_filename: metadata.original_filename,
        leaf: metadata.leaf,
        chain: metadata.chain,
    })
}

pub fn delete_leaf_certificate(root: &Path, fingerprint: &str) -> Result<()> {
    delete_if_exists(&leaf_p12_path(root, fingerprint))?;
    delete_if_exists(&leaf_certificate_pem_path(root, fingerprint))?;
    delete_if_exists(&leaf_chain_pem_path(root, fingerprint))?;
    delete_if_exists(&leaf_metadata_path(root, fingerprint))?;
    Ok(())
}

pub fn update_leaf_assignment(
    root: &Path,
    fingerprint: &str,
    assigned_services: &[String],
) -> Result<CertificateSummary> {
    let mut metadata: StoredLeafMetadata = read_json_file(&leaf_metadata_path(root, fingerprint))?;
    metadata.assigned_services = normalize_assigned_services(assigned_services)?;
    write_json_file(&leaf_metadata_path(root, fingerprint), &metadata)?;

    Ok(CertificateSummary {
        fingerprint: fingerprint.to_owned(),
        original_filename: metadata.original_filename,
        common_name: metadata.leaf.common_name,
        subject: metadata.leaf.subject,
        issuer: metadata.leaf.issuer,
        not_before: metadata.leaf.not_before,
        not_after: metadata.leaf.not_after,
        assigned_services: metadata.assigned_services,
    })
}

fn validate_leaf_certificate_trust(
    root: &Path,
    openssl_binary: &str,
    openssl_providers: &[String],
    leaf_certificate: &X509,
    chain_certificates: &[X509],
) -> Result<()> {
    let trusted_bundle = trusted_ca_bundle(root)?;
    if trusted_bundle.is_empty() {
        bail!("trusted CA store is empty");
    }

    let trusted_bundle_path = write_temp_file("trusted-ca-bundle", "pem", &trusted_bundle)?;
    let leaf_certificate_path =
        write_temp_file("leaf-certificate", "pem", &leaf_certificate.to_pem()?)?;
    let trusted_ca_entries = trusted_ca_log_entries(root)?;
    let leaf_summary = certificate_log_summary(leaf_certificate)?;
    let mut included_chain_entries = Vec::new();
    let mut skipped_self_signed_entries = Vec::new();

    let chain_path = if chain_certificates.is_empty() {
        None
    } else {
        let mut chain_pem = Vec::new();

        for certificate in chain_certificates {
            let summary = certificate_log_summary(certificate)?;
            if is_self_signed_certificate(certificate)? {
                skipped_self_signed_entries.push(summary);
                continue;
            }

            included_chain_entries.push(summary);
            chain_pem.extend(
                certificate
                    .to_pem()
                    .context("failed to serialize uploaded P12 chain certificates")?,
            );
        }

        if chain_pem.is_empty() {
            None
        } else {
            Some(write_temp_file("leaf-chain", "pem", &chain_pem)?)
        }
    };

    let mut command = Command::new(openssl_binary);
    command.arg("verify");
    est::append_openssl_provider_args(&mut command, openssl_binary, openssl_providers);
    command.arg("-CAfile").arg(&trusted_bundle_path);

    if let Some(chain_path) = &chain_path {
        command.arg("-untrusted").arg(chain_path);
    }

    command.arg(&leaf_certificate_path);

    let output = command.output().with_context(|| {
        format!("failed to execute trust verification using `{openssl_binary}`")
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let verification_log_path = write_leaf_verification_log(
        root,
        openssl_binary,
        openssl_providers,
        &leaf_summary,
        &trusted_ca_entries,
        &included_chain_entries,
        &skipped_self_signed_entries,
        &stdout,
        &stderr,
        output.status.success(),
    )?;

    cleanup_temp_file(&trusted_bundle_path);
    cleanup_temp_file(&leaf_certificate_path);
    if let Some(chain_path) = &chain_path {
        cleanup_temp_file(chain_path);
    }

    if !output.status.success() {
        bail!(
            "leaf certificate trust verification failed; verification log: {}; stdout: {}; stderr: {}",
            verification_log_path.display(),
            display_process_output(&stdout),
            display_process_output(&stderr)
        );
    }

    Ok(())
}

fn is_self_signed_certificate(certificate: &X509) -> Result<bool> {
    Ok(x509_name_to_string(certificate.subject_name())?
        == x509_name_to_string(certificate.issuer_name())?)
}

fn certificate_log_summary(certificate: &X509) -> Result<String> {
    Ok(format!(
        "subject={}; issuer={}; serial={}; fingerprint_sha256={}",
        x509_name_to_string(certificate.subject_name())?,
        x509_name_to_string(certificate.issuer_name())?,
        certificate
            .serial_number()
            .to_bn()
            .context("failed to extract certificate serial number for verification log")?
            .to_hex_str()
            .context("failed to format certificate serial number for verification log")?,
        fingerprint_hex(certificate)?,
    ))
}

fn trusted_ca_log_entries(root: &Path) -> Result<Vec<String>> {
    let mut entries = load_store_metadata::<StoredCaMetadata>(&trusted_ca_dir(root), "json")?
        .into_iter()
        .map(|(fingerprint, metadata)| {
            format!(
                "fingerprint={fingerprint}; original_filename={}; subject={}; issuer={}",
                metadata.original_filename,
                metadata.certificate.subject,
                metadata.certificate.issuer
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn write_leaf_verification_log(
    root: &Path,
    openssl_binary: &str,
    openssl_providers: &[String],
    leaf_summary: &str,
    trusted_ca_entries: &[String],
    included_chain_entries: &[String],
    skipped_self_signed_entries: &[String],
    stdout: &str,
    stderr: &str,
    success: bool,
) -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let path = verification_log_dir(root).join(format!("leaf-verify-{stamp}.log"));

    let mut content = String::new();
    content.push_str(&format!("timestamp_unix_nanos={stamp}\n"));
    content.push_str(&format!("openssl_binary={openssl_binary}\n"));
    content.push_str(&format!(
        "openssl_providers={}\n",
        if openssl_providers.is_empty() {
            "(none)".to_owned()
        } else {
            openssl_providers.join(",")
        }
    ));
    content.push_str(&format!("success={success}\n\n"));
    content.push_str("[leaf]\n");
    content.push_str(leaf_summary);
    content.push_str("\n\n[trusted_ca_store]\n");
    if trusted_ca_entries.is_empty() {
        content.push_str("(empty)\n");
    } else {
        for entry in trusted_ca_entries {
            content.push_str(entry);
            content.push('\n');
        }
    }
    content.push_str("\n[provided_chain_used_as_untrusted]\n");
    if included_chain_entries.is_empty() {
        content.push_str("(none)\n");
    } else {
        for entry in included_chain_entries {
            content.push_str(entry);
            content.push('\n');
        }
    }
    content.push_str("\n[provided_chain_skipped_as_self_signed]\n");
    if skipped_self_signed_entries.is_empty() {
        content.push_str("(none)\n");
    } else {
        for entry in skipped_self_signed_entries {
            content.push_str(entry);
            content.push('\n');
        }
    }
    content.push_str("\n[openssl_verify_stdout]\n");
    content.push_str(display_process_output(stdout));
    content.push_str("\n\n[openssl_verify_stderr]\n");
    content.push_str(display_process_output(stderr));
    content.push('\n');

    fs::write(&path, &content)
        .with_context(|| format!("failed to write leaf verification log `{}`", path.display()))?;

    let latest_path = verification_log_dir(root).join("leaf-verify-latest.log");
    fs::write(&latest_path, &content).with_context(|| {
        format!(
            "failed to write leaf verification log `{}`",
            latest_path.display()
        )
    })?;

    Ok(path)
}

fn display_process_output(output: &str) -> &str {
    if output.trim().is_empty() {
        "<empty>"
    } else {
        output
    }
}

fn trusted_ca_bundle(root: &Path) -> Result<Vec<u8>> {
    let mut bundle = Vec::new();

    for entry in fs::read_dir(trusted_ca_dir(root)).with_context(|| {
        format!(
            "failed to read trusted CA store `{}`",
            trusted_ca_dir(root).display()
        )
    })? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("pem")
        {
            continue;
        }

        bundle.extend(fs::read(entry.path()).with_context(|| {
            format!(
                "failed to read trusted CA certificate `{}`",
                entry.path().display()
            )
        })?);
    }

    Ok(bundle)
}

fn missing_trusted_ca_message(certificate: &X509) -> Result<String> {
    Ok(format!(
        "The Trusted CA must be loaded first for leaf certificate issuer {}.",
        x509_name_to_string(certificate.issuer_name())?
    ))
}

fn decode_certificate(certificate: &X509) -> Result<DecodedCertificate> {
    let fingerprint_sha256 = fingerprint_hex(certificate)?;
    let public_key = certificate
        .public_key()
        .context("failed to extract certificate public key")?;
    let mut san_dns = Vec::new();
    let mut san_email = Vec::new();

    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        for name in subject_alt_names {
            if let Some(dns_name) = name.dnsname() {
                san_dns.push(dns_name.to_owned());
            }
            if let Some(email) = name.email() {
                san_email.push(email.to_owned());
            }
        }
    }

    Ok(DecodedCertificate {
        common_name: extract_common_name(certificate.subject_name())?,
        subject: x509_name_to_string(certificate.subject_name())?,
        issuer: x509_name_to_string(certificate.issuer_name())?,
        serial_number: certificate
            .serial_number()
            .to_bn()
            .context("failed to extract certificate serial number")?
            .to_hex_str()
            .context("failed to format certificate serial number")?
            .to_string(),
        not_before: certificate.not_before().to_string(),
        not_after: certificate.not_after().to_string(),
        fingerprint_sha256,
        san_dns,
        san_email,
        key_algorithm: public_key_algorithm(public_key.id()),
        key_bits: public_key.bits(),
        pem: String::from_utf8(
            certificate
                .to_pem()
                .context("failed to serialize certificate to PEM")?,
        )
        .context("certificate PEM was not valid UTF-8")?,
    })
}

fn fingerprint_hex(certificate: &X509) -> Result<String> {
    let digest = certificate
        .digest(MessageDigest::sha256())
        .context("failed to calculate certificate fingerprint")?;
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn default_common_name() -> String {
    "—".to_owned()
}

fn extract_common_name(name: &X509NameRef) -> Result<String> {
    for entry in name.entries() {
        let short_name = entry.object().nid().short_name().unwrap_or("UNKNOWN");
        if short_name != "CN" {
            continue;
        }

        let value = entry
            .data()
            .as_utf8()
            .map(|value| value.to_string())
            .context("failed to decode X.509 common name as UTF-8")?;
        return Ok(value);
    }

    Ok(default_common_name())
}

fn normalize_assigned_services(assigned_services: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::new();

    for service in assigned_services {
        let value = service.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }

        if !matches!(value.as_str(), "est" | "webui") {
            bail!("unsupported leaf certificate assignment `{value}`");
        }

        if !normalized.iter().any(|entry| entry == &value) {
            normalized.push(value);
        }
    }

    normalized.sort();
    Ok(normalized)
}

fn x509_name_to_string(name: &X509NameRef) -> Result<String> {
    let mut parts = Vec::new();

    for entry in name.entries() {
        let short_name = entry.object().nid().short_name().unwrap_or("UNKNOWN");
        let value = entry
            .data()
            .as_utf8()
            .map(|value| value.to_string())
            .context("failed to decode X.509 name entry as UTF-8")?;
        parts.push(format!("{short_name}={value}"));
    }

    Ok(parts.join(", "))
}

fn public_key_algorithm(key_id: PKeyId) -> String {
    match key_id {
        PKeyId::RSA => "RSA".to_owned(),
        PKeyId::EC => "ECDSA".to_owned(),
        PKeyId::ED25519 => "ED25519".to_owned(),
        PKeyId::ED448 => "ED448".to_owned(),
        _ => format!("{key_id:?}"),
    }
}

fn write_json_file<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    fs::write(
        path,
        serde_json::to_vec_pretty(value).context("failed to serialize JSON metadata")?,
    )
    .with_context(|| format!("failed to write `{}`", path.display()))?;
    Ok(())
}

fn read_json_file<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let content = fs::read(path).with_context(|| format!("failed to read `{}`", path.display()))?;
    serde_json::from_slice(&content)
        .with_context(|| format!("failed to parse `{}`", path.display()))
}

fn load_store_metadata<T>(directory: &Path, extension: &str) -> Result<Vec<(String, T)>>
where
    T: for<'de> Deserialize<'de>,
{
    let mut metadata = Vec::new();

    if !directory.exists() {
        return Ok(metadata);
    }

    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read `{}`", directory.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some(extension)
        {
            continue;
        }

        let Some(fingerprint) = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };

        metadata.push((fingerprint, read_json_file(&entry.path())?));
    }

    Ok(metadata)
}

fn trusted_ca_dir(root: &Path) -> PathBuf {
    root.join("trusted-ca")
}

fn leaf_dir(root: &Path) -> PathBuf {
    root.join("leaf")
}

fn verification_log_dir(root: &Path) -> PathBuf {
    root.join("verification")
}

fn trusted_ca_pem_path(root: &Path, fingerprint: &str) -> PathBuf {
    trusted_ca_dir(root).join(format!("{fingerprint}.pem"))
}

fn trusted_ca_metadata_path(root: &Path, fingerprint: &str) -> PathBuf {
    trusted_ca_dir(root).join(format!("{fingerprint}.json"))
}

fn leaf_p12_path(root: &Path, fingerprint: &str) -> PathBuf {
    leaf_dir(root).join(format!("{fingerprint}.p12"))
}

fn leaf_certificate_pem_path(root: &Path, fingerprint: &str) -> PathBuf {
    leaf_dir(root).join(format!("{fingerprint}.leaf.pem"))
}

fn leaf_chain_pem_path(root: &Path, fingerprint: &str) -> PathBuf {
    leaf_dir(root).join(format!("{fingerprint}.chain.pem"))
}

fn leaf_metadata_path(root: &Path, fingerprint: &str) -> PathBuf {
    leaf_dir(root).join(format!("{fingerprint}.json"))
}

fn delete_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("failed to remove `{}`", path.display()))?;
    }
    Ok(())
}

fn write_temp_file(prefix: &str, extension: &str, content: &[u8]) -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let path = env::temp_dir().join(format!("{prefix}-{stamp}.{extension}"));
    fs::write(&path, content)
        .with_context(|| format!("failed to write temporary file `{}`", path.display()))?;
    Ok(path)
}

fn cleanup_temp_file(path: &Path) {
    let _ = fs::remove_file(path);
}
