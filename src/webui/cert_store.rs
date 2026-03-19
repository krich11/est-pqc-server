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
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedCertificate {
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
    Ok(())
}

pub fn list_trusted_ca(root: &Path) -> Result<Vec<CertificateSummary>> {
    let mut entries = load_store_metadata::<StoredCaMetadata>(&trusted_ca_dir(root), "json")?
        .into_iter()
        .map(|(fingerprint, metadata)| CertificateSummary {
            fingerprint,
            original_filename: metadata.original_filename,
            subject: metadata.certificate.subject,
            issuer: metadata.certificate.issuer,
            not_before: metadata.certificate.not_before,
            not_after: metadata.certificate.not_after,
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
        subject: certificate_detail.subject,
        issuer: certificate_detail.issuer,
        not_before: certificate_detail.not_before,
        not_after: certificate_detail.not_after,
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
        .map(|(fingerprint, metadata)| CertificateSummary {
            fingerprint,
            original_filename: metadata.original_filename,
            subject: metadata.leaf.subject,
            issuer: metadata.leaf.issuer,
            not_before: metadata.leaf.not_before,
            not_after: metadata.leaf.not_after,
        })
        .collect::<Vec<_>>();

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

    validate_leaf_certificate_trust(root, openssl_binary, &leaf_certificate, &chain_certificates)
        .map_err(|_| anyhow!(trust_error_message.clone()))?;

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
    };
    write_json_file(&leaf_metadata_path(root, &fingerprint), &metadata)?;

    Ok(CertificateSummary {
        fingerprint,
        original_filename: metadata.original_filename,
        subject: leaf_detail.subject,
        issuer: leaf_detail.issuer,
        not_before: leaf_detail.not_before,
        not_after: leaf_detail.not_after,
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

fn validate_leaf_certificate_trust(
    root: &Path,
    openssl_binary: &str,
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
    let chain_path = if chain_certificates.is_empty() {
        None
    } else {
        let chain_pem = chain_certificates
            .iter()
            .map(|certificate| certificate.to_pem())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to serialize uploaded P12 chain certificates")?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        Some(write_temp_file("leaf-chain", "pem", &chain_pem)?)
    };

    let mut command = Command::new(openssl_binary);
    command
        .arg("verify")
        .arg("-CAfile")
        .arg(&trusted_bundle_path);

    if let Some(chain_path) = &chain_path {
        command.arg("-untrusted").arg(chain_path);
    }

    command.arg(&leaf_certificate_path);

    let output = command.output().with_context(|| {
        format!("failed to execute trust verification using `{openssl_binary}`")
    })?;

    cleanup_temp_file(&trusted_bundle_path);
    cleanup_temp_file(&leaf_certificate_path);
    if let Some(chain_path) = &chain_path {
        cleanup_temp_file(chain_path);
    }

    if !output.status.success() {
        bail!(
            "leaf certificate trust verification failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
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
