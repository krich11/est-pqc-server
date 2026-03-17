use anyhow::{bail, Context, Result};
use axum::body::Body;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::{
    body::Incoming,
    header::{HeaderName, CONTENT_TYPE, RETRY_AFTER},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id as PKeyId, PKey, Private},
    sha::sha256,
    ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslVerifyMode, SslVersion},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        X509NameRef, X509Req, X509,
    },
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    convert::Infallible,
    env, fs,
    path::{Path, PathBuf},
    pin::Pin,
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tracing::{error, info};

const DEFAULT_OPENSSL_DIR: &str = "/opt/homebrew/opt/openssl@3.5";
const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0";
const DEFAULT_TLS_VERSION: &str = "TLS1.3";
const DEFAULT_TLS_CIPHER_SUITE: &str = "TLS_AES_256_GCM_SHA384";
const DEFAULT_KEY_TYPE: &str = "rsa2048";
const DEFAULT_CA_CERTIFICATE_PATH: &str = "demo/demo-ca.crt";
const DEFAULT_CA_PRIVATE_KEY_PATH: &str = "demo/demo-ca.key";
const DEFAULT_CLIENT_AUTH_CA_CERTIFICATE_PATH: &str = "demo/demo-ca.crt";
const DEFAULT_TLS_CERTIFICATE_PATH: &str = "demo/rsa-2048-server.crt";
const DEFAULT_TLS_PRIVATE_KEY_PATH: &str = "demo/rsa-2048-server.key";
const DEFAULT_ENROLLMENT_STORAGE_DIR: &str = "logs/enrollments";
const DEFAULT_PENDING_ENROLLMENT_DIR: &str = "logs/pending";
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_RETRY_AFTER_SECONDS: u32 = 60;
const DEFAULT_WEBUI_LISTEN_ADDRESS: &str = "127.0.0.1";
const DEFAULT_WEBUI_ADMIN_USERNAME: &str = "admin";
const DEFAULT_SYSTEMD_UNIT_NAME: &str = "est-server";

const CSR_ATTRS_EMPTY_SEQUENCE: &[u8] = &[0x30, 0x00];
const CONTENT_TRANSFER_ENCODING_HEADER: &str = "content-transfer-encoding";
const PREFER_HEADER: &str = "prefer";
const RESPOND_ASYNC_PREFERENCE: &str = "respond-async";

const CACERTS_PATH: &str = "/.well-known/est/cacerts";
const CSRATTRS_PATH: &str = "/.well-known/est/csrattrs";
const SIMPLE_ENROLL_PATH: &str = "/.well-known/est/simpleenroll";
const SIMPLE_REENROLL_PATH: &str = "/.well-known/est/simplereenroll";
const SERVER_KEYGEN_PATH: &str = "/.well-known/est/serverkeygen";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EnrollmentAction {
    #[default]
    Auto,
    Manual,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EnrollmentRule {
    pub name: String,
    pub match_subject_cn: Option<String>,
    pub match_subject_ou: Option<String>,
    pub match_subject_o: Option<String>,
    pub match_san_dns: Option<String>,
    pub match_san_email: Option<String>,
    pub match_client_cert_issuer: Option<String>,
    pub match_key_type: Option<String>,
    pub action: EnrollmentAction,
    pub reject_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnrollmentConfig {
    pub default_action: EnrollmentAction,
    pub rules: Vec<EnrollmentRule>,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            default_action: EnrollmentAction::Auto,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WebUiAuthMode {
    #[default]
    Basic,
    Mtls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebUiConfig {
    pub enabled: bool,
    pub listen_address: String,
    pub listen_port: u16,
    pub tls_certificate_path: String,
    pub tls_private_key_path: String,
    pub auth_mode: WebUiAuthMode,
    pub admin_username: String,
    pub admin_password_hash: String,
    pub systemd_unit_name: String,
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: DEFAULT_WEBUI_LISTEN_ADDRESS.to_owned(),
            listen_port: 9443,
            tls_certificate_path: DEFAULT_TLS_CERTIFICATE_PATH.to_owned(),
            tls_private_key_path: DEFAULT_TLS_PRIVATE_KEY_PATH.to_owned(),
            auth_mode: WebUiAuthMode::Basic,
            admin_username: DEFAULT_WEBUI_ADMIN_USERNAME.to_owned(),
            admin_password_hash: String::new(),
            systemd_unit_name: DEFAULT_SYSTEMD_UNIT_NAME.to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub tls_version: String,
    pub preferred_tls_cipher_suite: String,
    pub key_type: String,
    pub enable_fips: bool,
    pub openssl_dir: String,
    pub openssl_binary: String,
    pub ca_certificate_path: String,
    pub ca_private_key_path: String,
    pub client_auth_ca_certificate_path: String,
    pub tls_certificate_path: String,
    pub tls_private_key_path: String,
    pub enrollment_storage_dir: String,
    pub pending_enrollment_dir: String,
    pub max_request_body_bytes: usize,
    pub default_retry_after_seconds: u32,
    pub ml_kem_supported: bool,
    pub ml_dsa_supported: bool,
    pub webui: WebUiConfig,
    pub enrollment: EnrollmentConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: DEFAULT_LISTEN_ADDRESS.to_owned(),
            listen_port: 8443,
            tls_version: DEFAULT_TLS_VERSION.to_owned(),
            preferred_tls_cipher_suite: DEFAULT_TLS_CIPHER_SUITE.to_owned(),
            key_type: DEFAULT_KEY_TYPE.to_owned(),
            enable_fips: false,
            openssl_dir: DEFAULT_OPENSSL_DIR.to_owned(),
            openssl_binary: String::new(),
            ca_certificate_path: DEFAULT_CA_CERTIFICATE_PATH.to_owned(),
            ca_private_key_path: DEFAULT_CA_PRIVATE_KEY_PATH.to_owned(),
            client_auth_ca_certificate_path: DEFAULT_CLIENT_AUTH_CA_CERTIFICATE_PATH.to_owned(),
            tls_certificate_path: DEFAULT_TLS_CERTIFICATE_PATH.to_owned(),
            tls_private_key_path: DEFAULT_TLS_PRIVATE_KEY_PATH.to_owned(),
            enrollment_storage_dir: DEFAULT_ENROLLMENT_STORAGE_DIR.to_owned(),
            pending_enrollment_dir: DEFAULT_PENDING_ENROLLMENT_DIR.to_owned(),
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            default_retry_after_seconds: DEFAULT_RETRY_AFTER_SECONDS,
            ml_kem_supported: false,
            ml_dsa_supported: false,
            webui: WebUiConfig::default(),
            enrollment: EnrollmentConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerConfigOverrides {
    pub listen_address: Option<String>,
    pub listen_port: Option<u16>,
    pub tls_version: Option<String>,
    pub preferred_tls_cipher_suite: Option<String>,
    pub key_type: Option<String>,
    pub enable_fips: Option<bool>,
    pub openssl_dir: Option<String>,
    pub openssl_binary: Option<String>,
    pub ca_certificate_path: Option<String>,
    pub ca_private_key_path: Option<String>,
    pub client_auth_ca_certificate_path: Option<String>,
    pub tls_certificate_path: Option<String>,
    pub tls_private_key_path: Option<String>,
    pub enrollment_storage_dir: Option<String>,
    pub pending_enrollment_dir: Option<String>,
    pub max_request_body_bytes: Option<usize>,
    pub default_retry_after_seconds: Option<u32>,
    pub ml_kem_supported: Option<bool>,
    pub ml_dsa_supported: Option<bool>,
    pub webui_enabled: Option<bool>,
    pub webui_listen_address: Option<String>,
    pub webui_listen_port: Option<u16>,
    pub webui_tls_certificate_path: Option<String>,
    pub webui_tls_private_key_path: Option<String>,
    pub webui_auth_mode: Option<WebUiAuthMode>,
    pub webui_admin_username: Option<String>,
    pub webui_admin_password_hash: Option<String>,
    pub webui_systemd_unit_name: Option<String>,
}

#[derive(Clone)]
struct ConnectionMeta {
    peer_certificate: Option<X509>,
    tls_unique: Vec<u8>,
}

#[derive(Clone)]
struct EstState {
    config: ServerConfig,
    openssl_binary: String,
    ca_certificate: X509,
    ca_private_key: PKey<Private>,
    ca_certificate_path: PathBuf,
    client_auth_ca_certificate_path: PathBuf,
    tls_certificate_path: PathBuf,
    tls_private_key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequestContext {
    pub operation: String,
    pub artifact_id: String,
    pub subject_cn: Option<String>,
    pub subject_ou: Option<String>,
    pub subject_o: Option<String>,
    pub san_dns: Vec<String>,
    pub san_email: Vec<String>,
    pub client_cert_issuer: Option<String>,
    pub key_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PendingEnrollmentState {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEnrollmentRecord {
    pub operation: String,
    pub artifact_id: String,
    pub retry_after_seconds: u32,
    pub state: PendingEnrollmentState,
    pub matched_rule_name: Option<String>,
    pub action: EnrollmentAction,
    pub reject_reason: Option<String>,
    pub context: EnrollmentRequestContext,
}

#[derive(Debug, Clone)]
struct EnrollmentDecision {
    action: EnrollmentAction,
    matched_rule_name: Option<String>,
    reject_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentArtifactSummary {
    pub operation: String,
    pub artifact_id: String,
    pub csr_path: String,
    pub certificate_path: Option<String>,
}

#[derive(Debug, Error)]
#[error("{message}")]
struct HttpStatusError {
    status: StatusCode,
    message: String,
    retry_after: Option<u32>,
}

impl HttpStatusError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
        }
    }
}

pub async fn run_server_with_overrides(
    config_path: &Path,
    overrides: &ServerConfigOverrides,
) -> Result<()> {
    let mut config = load_server_config_or_default(config_path)?;
    apply_overrides(&mut config, overrides);
    normalize_server_config(&mut config);
    validate_server_config(&config)?;

    fs::create_dir_all(&config.enrollment_storage_dir).with_context(|| {
        format!(
            "failed to create enrollment storage dir `{}`",
            config.enrollment_storage_dir
        )
    })?;
    fs::create_dir_all(&config.pending_enrollment_dir).with_context(|| {
        format!(
            "failed to create pending enrollment dir `{}`",
            config.pending_enrollment_dir
        )
    })?;

    let state = Arc::new(load_state(config)?);
    let acceptor = Arc::new(build_ssl_acceptor(&state)?);
    let bind_address = format!(
        "{}:{}",
        state.config.listen_address, state.config.listen_port
    );
    let listener = TcpListener::bind(&bind_address)
        .await
        .with_context(|| format!("failed to bind EST listener on `{bind_address}`"))?;

    info!(
        "EST HTTPS listener started on {bind_address} using config {}",
        config_path.display()
    );

    loop {
        let (stream, remote_address) = listener
            .accept()
            .await
            .context("failed to accept TCP connection")?;

        let acceptor = Arc::clone(&acceptor);
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            if let Err(error) = serve_est_connection(stream, acceptor, state).await {
                error!("EST connection from {remote_address} failed: {error:#}");
            }
        });
    }
}

fn load_server_config_or_default(config_path: &Path) -> Result<ServerConfig> {
    if !config_path.exists() {
        return Ok(ServerConfig::default());
    }

    let content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read `{}`", config_path.display()))?;
    toml::from_str(&content).with_context(|| format!("failed to parse `{}`", config_path.display()))
}

fn apply_overrides(config: &mut ServerConfig, overrides: &ServerConfigOverrides) {
    if let Some(value) = &overrides.listen_address {
        config.listen_address.clone_from(value);
    }
    if let Some(value) = overrides.listen_port {
        config.listen_port = value;
    }
    if let Some(value) = &overrides.tls_version {
        config.tls_version.clone_from(value);
    }
    if let Some(value) = &overrides.preferred_tls_cipher_suite {
        config.preferred_tls_cipher_suite.clone_from(value);
    }
    if let Some(value) = &overrides.key_type {
        config.key_type.clone_from(value);
    }
    if let Some(value) = overrides.enable_fips {
        config.enable_fips = value;
    }
    if let Some(value) = &overrides.openssl_dir {
        config.openssl_dir.clone_from(value);
    }
    if let Some(value) = &overrides.openssl_binary {
        config.openssl_binary.clone_from(value);
    }
    if let Some(value) = &overrides.ca_certificate_path {
        config.ca_certificate_path.clone_from(value);
    }
    if let Some(value) = &overrides.ca_private_key_path {
        config.ca_private_key_path.clone_from(value);
    }
    if let Some(value) = &overrides.client_auth_ca_certificate_path {
        config.client_auth_ca_certificate_path.clone_from(value);
    }
    if let Some(value) = &overrides.tls_certificate_path {
        config.tls_certificate_path.clone_from(value);
    }
    if let Some(value) = &overrides.tls_private_key_path {
        config.tls_private_key_path.clone_from(value);
    }
    if let Some(value) = &overrides.enrollment_storage_dir {
        config.enrollment_storage_dir.clone_from(value);
    }
    if let Some(value) = &overrides.pending_enrollment_dir {
        config.pending_enrollment_dir.clone_from(value);
    }
    if let Some(value) = overrides.max_request_body_bytes {
        config.max_request_body_bytes = value;
    }
    if let Some(value) = overrides.default_retry_after_seconds {
        config.default_retry_after_seconds = value;
    }
    if let Some(value) = overrides.ml_kem_supported {
        config.ml_kem_supported = value;
    }
    if let Some(value) = overrides.ml_dsa_supported {
        config.ml_dsa_supported = value;
    }
    if let Some(value) = overrides.webui_enabled {
        config.webui.enabled = value;
    }
    if let Some(value) = &overrides.webui_listen_address {
        config.webui.listen_address.clone_from(value);
    }
    if let Some(value) = overrides.webui_listen_port {
        config.webui.listen_port = value;
    }
    if let Some(value) = &overrides.webui_tls_certificate_path {
        config.webui.tls_certificate_path.clone_from(value);
    }
    if let Some(value) = &overrides.webui_tls_private_key_path {
        config.webui.tls_private_key_path.clone_from(value);
    }
    if let Some(value) = &overrides.webui_auth_mode {
        config.webui.auth_mode = value.clone();
    }
    if let Some(value) = &overrides.webui_admin_username {
        config.webui.admin_username.clone_from(value);
    }
    if let Some(value) = &overrides.webui_admin_password_hash {
        config.webui.admin_password_hash.clone_from(value);
    }
    if let Some(value) = &overrides.webui_systemd_unit_name {
        config.webui.systemd_unit_name.clone_from(value);
    }
}

fn normalize_server_config(config: &mut ServerConfig) {
    if config.listen_address.trim().is_empty() {
        config.listen_address = DEFAULT_LISTEN_ADDRESS.to_owned();
    }
    if config.tls_version.trim().is_empty() {
        config.tls_version = DEFAULT_TLS_VERSION.to_owned();
    }
    if config.preferred_tls_cipher_suite.trim().is_empty() {
        config.preferred_tls_cipher_suite = DEFAULT_TLS_CIPHER_SUITE.to_owned();
    }
    if config.key_type.trim().is_empty() {
        config.key_type = DEFAULT_KEY_TYPE.to_owned();
    }
    if config.ca_certificate_path.trim().is_empty() {
        config.ca_certificate_path = DEFAULT_CA_CERTIFICATE_PATH.to_owned();
    }
    if config.ca_private_key_path.trim().is_empty() {
        config.ca_private_key_path = DEFAULT_CA_PRIVATE_KEY_PATH.to_owned();
    }
    if config.client_auth_ca_certificate_path.trim().is_empty() {
        config.client_auth_ca_certificate_path = config.ca_certificate_path.clone();
    }
    if config.tls_certificate_path.trim().is_empty() {
        config.tls_certificate_path = DEFAULT_TLS_CERTIFICATE_PATH.to_owned();
    }
    if config.tls_private_key_path.trim().is_empty() {
        config.tls_private_key_path = DEFAULT_TLS_PRIVATE_KEY_PATH.to_owned();
    }
    if config.enrollment_storage_dir.trim().is_empty() {
        config.enrollment_storage_dir = DEFAULT_ENROLLMENT_STORAGE_DIR.to_owned();
    }
    if config.pending_enrollment_dir.trim().is_empty() {
        config.pending_enrollment_dir = DEFAULT_PENDING_ENROLLMENT_DIR.to_owned();
    }
    if config.webui.listen_address.trim().is_empty() {
        config.webui.listen_address = DEFAULT_WEBUI_LISTEN_ADDRESS.to_owned();
    }
    if config.webui.tls_certificate_path.trim().is_empty() {
        config.webui.tls_certificate_path = config.tls_certificate_path.clone();
    }
    if config.webui.tls_private_key_path.trim().is_empty() {
        config.webui.tls_private_key_path = config.tls_private_key_path.clone();
    }
    if config.webui.admin_username.trim().is_empty() {
        config.webui.admin_username = DEFAULT_WEBUI_ADMIN_USERNAME.to_owned();
    }
    if config.webui.systemd_unit_name.trim().is_empty() {
        config.webui.systemd_unit_name = DEFAULT_SYSTEMD_UNIT_NAME.to_owned();
    }
}

fn validate_server_config(config: &ServerConfig) -> Result<()> {
    if config.tls_version != DEFAULT_TLS_VERSION {
        bail!(
            "TLS 1.3 is required for EST, found `{}` in config",
            config.tls_version
        );
    }

    if config.listen_address.trim().is_empty() {
        bail!("listen_address must not be empty");
    }
    if config.listen_port == 0 {
        bail!("listen_port must be greater than zero");
    }
    if config.preferred_tls_cipher_suite.trim().is_empty() {
        bail!("preferred_tls_cipher_suite must not be empty");
    }
    if config.key_type.trim().is_empty() {
        bail!("key_type must not be empty");
    }
    if config.ca_certificate_path.trim().is_empty() {
        bail!("ca_certificate_path must not be empty");
    }
    if config.ca_private_key_path.trim().is_empty() {
        bail!("ca_private_key_path must not be empty");
    }
    if config.client_auth_ca_certificate_path.trim().is_empty() {
        bail!("client_auth_ca_certificate_path must not be empty");
    }
    if config.tls_certificate_path.trim().is_empty() {
        bail!("tls_certificate_path must not be empty");
    }
    if config.tls_private_key_path.trim().is_empty() {
        bail!("tls_private_key_path must not be empty");
    }
    if config.enrollment_storage_dir.trim().is_empty() {
        bail!("enrollment_storage_dir must not be empty");
    }
    if config.pending_enrollment_dir.trim().is_empty() {
        bail!("pending_enrollment_dir must not be empty");
    }
    if config.max_request_body_bytes == 0 {
        bail!("max_request_body_bytes must be greater than zero");
    }
    if config.default_retry_after_seconds == 0 {
        bail!("default_retry_after_seconds must be greater than zero");
    }
    if config.webui.enabled {
        if config.webui.listen_address.trim().is_empty() {
            bail!("webui.listen_address must not be empty when WebUI is enabled");
        }
        if config.webui.listen_port == 0 {
            bail!("webui.listen_port must be greater than zero when WebUI is enabled");
        }
        if config.webui.tls_certificate_path.trim().is_empty() {
            bail!("webui.tls_certificate_path must not be empty when WebUI is enabled");
        }
        if config.webui.tls_private_key_path.trim().is_empty() {
            bail!("webui.tls_private_key_path must not be empty when WebUI is enabled");
        }
        if config.webui.admin_username.trim().is_empty() {
            bail!("webui.admin_username must not be empty when WebUI basic auth is enabled");
        }
        if matches!(config.webui.auth_mode, WebUiAuthMode::Basic)
            && config.webui.admin_password_hash.trim().is_empty()
        {
            bail!("webui.admin_password_hash must not be empty when WebUI basic auth is enabled");
        }
        if config.webui.systemd_unit_name.trim().is_empty() {
            bail!("webui.systemd_unit_name must not be empty when WebUI is enabled");
        }
    }

    Ok(())
}

fn load_state(config: ServerConfig) -> Result<EstState> {
    let openssl_binary = detect_openssl_binary(&config);
    let ca_certificate_path = PathBuf::from(&config.ca_certificate_path);
    let ca_private_key_path = PathBuf::from(&config.ca_private_key_path);
    let client_auth_ca_certificate_path = PathBuf::from(&config.client_auth_ca_certificate_path);
    let tls_certificate_path = PathBuf::from(&config.tls_certificate_path);
    let tls_private_key_path = PathBuf::from(&config.tls_private_key_path);

    let ca_certificate = X509::from_pem(
        &fs::read(&ca_certificate_path)
            .with_context(|| format!("failed to read `{}`", ca_certificate_path.display()))?,
    )
    .context("failed to parse CA certificate")?;

    let ca_private_key = PKey::private_key_from_pem(
        &fs::read(&ca_private_key_path)
            .with_context(|| format!("failed to read `{}`", ca_private_key_path.display()))?,
    )
    .context("failed to parse CA private key")?;

    Ok(EstState {
        config,
        openssl_binary,
        ca_certificate,
        ca_private_key,
        ca_certificate_path,
        client_auth_ca_certificate_path,
        tls_certificate_path,
        tls_private_key_path,
    })
}

fn detect_openssl_binary(config: &ServerConfig) -> String {
    if let Ok(value) = env::var("OPENSSL") {
        let path = Path::new(&value);
        if !value.is_empty() && (!path.is_absolute() || path.exists()) {
            return value;
        }
    }

    if !config.openssl_binary.is_empty() {
        let configured = Path::new(&config.openssl_binary);
        if !configured.is_absolute() || configured.exists() {
            return config.openssl_binary.clone();
        }
    }

    let openssl_dir = if config.openssl_dir.is_empty() {
        DEFAULT_OPENSSL_DIR.to_owned()
    } else {
        config.openssl_dir.clone()
    };

    let candidate = Path::new(&openssl_dir).join("bin").join("openssl");
    if candidate.exists() {
        return candidate.to_string_lossy().into_owned();
    }

    "openssl".to_owned()
}

fn build_ssl_acceptor(state: &EstState) -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .context("failed to build SSL acceptor")?;

    builder
        .set_certificate_file(&state.tls_certificate_path, SslFiletype::PEM)
        .with_context(|| {
            format!(
                "failed to load TLS certificate `{}`",
                state.tls_certificate_path.display()
            )
        })?;
    builder
        .set_private_key_file(&state.tls_private_key_path, SslFiletype::PEM)
        .with_context(|| {
            format!(
                "failed to load TLS private key `{}`",
                state.tls_private_key_path.display()
            )
        })?;
    builder
        .set_ca_file(&state.client_auth_ca_certificate_path)
        .with_context(|| {
            format!(
                "failed to load client auth CA file `{}`",
                state.client_auth_ca_certificate_path.display()
            )
        })?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("failed to set minimum TLS version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("failed to set maximum TLS version")?;
    builder
        .set_ciphersuites(&state.config.preferred_tls_cipher_suite)
        .with_context(|| {
            format!(
                "failed to set TLS 1.3 cipher suite `{}`",
                state.config.preferred_tls_cipher_suite
            )
        })?;

    Ok(builder.build())
}

async fn serve_est_connection(
    stream: TcpStream,
    acceptor: Arc<SslAcceptor>,
    state: Arc<EstState>,
) -> Result<()> {
    let ssl = Ssl::new(acceptor.context()).context("failed to create SSL connection")?;
    let mut tls_stream = SslStream::new(ssl, stream).context("failed to wrap TCP stream in TLS")?;
    Pin::new(&mut tls_stream)
        .accept()
        .await
        .context("TLS handshake failed")?;

    let connection_meta = ConnectionMeta {
        peer_certificate: tls_stream.ssl().peer_certificate(),
        tls_unique: tls_unique_binding(tls_stream.ssl()),
    };

    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        let connection_meta = connection_meta.clone();
        async move { handle_est_request(request, state, connection_meta).await }
    });

    http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), service)
        .await
        .context("HTTP/1.1 EST service failed")?;

    Ok(())
}

fn tls_unique_binding(ssl: &openssl::ssl::SslRef) -> Vec<u8> {
    let mut server_finished = [0_u8; 64];
    let mut peer_finished = [0_u8; 64];
    let server_len = ssl.finished(&mut server_finished);
    let peer_len = ssl.peer_finished(&mut peer_finished);

    let mut binding = Vec::with_capacity(server_len + peer_len);
    binding.extend_from_slice(&server_finished[..server_len]);
    binding.extend_from_slice(&peer_finished[..peer_len]);
    binding
}

async fn handle_est_request(
    request: Request<Incoming>,
    state: Arc<EstState>,
    connection_meta: ConnectionMeta,
) -> Result<Response<Body>, Infallible> {
    let response = match route_est_request(request, &state, &connection_meta).await {
        Ok(response) => response,
        Err(error) => {
            if let Some(http_error) = error.downcast_ref::<HttpStatusError>() {
                error_response(
                    http_error.status,
                    &http_error.message,
                    http_error.retry_after,
                )
            } else {
                error!("unhandled EST server error: {error:#}");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal EST server error",
                    None,
                )
            }
        }
    };

    Ok(response)
}

async fn route_est_request(
    request: Request<Incoming>,
    state: &EstState,
    connection_meta: &ConnectionMeta,
) -> Result<Response<Body>> {
    let path = request.uri().path().to_owned();

    match (request.method(), path.as_str()) {
        (&Method::GET, CACERTS_PATH) => handle_cacerts(state).await,
        (&Method::GET, CSRATTRS_PATH) => Ok(binary_response(
            StatusCode::OK,
            "application/csrattrs",
            CSR_ATTRS_EMPTY_SEQUENCE.to_vec(),
        )),
        (&Method::POST, SIMPLE_ENROLL_PATH) => {
            require_content_type(&request, "application/pkcs10")?;
            require_peer_certificate(connection_meta)?;
            require_tls_unique(connection_meta)?;
            let prefer_async = prefers_async_response(&request);
            let body = collect_request_body(request, state.config.max_request_body_bytes).await?;
            handle_simple_enroll(state, connection_meta, &body, false, prefer_async).await
        }
        (&Method::POST, SIMPLE_REENROLL_PATH) => {
            require_content_type(&request, "application/pkcs10")?;
            require_peer_certificate(connection_meta)?;
            require_tls_unique(connection_meta)?;
            let prefer_async = prefers_async_response(&request);
            let body = collect_request_body(request, state.config.max_request_body_bytes).await?;
            handle_simple_enroll(state, connection_meta, &body, true, prefer_async).await
        }
        (&Method::POST, SERVER_KEYGEN_PATH) => {
            require_content_type(&request, "application/pkcs10")?;
            require_peer_certificate(connection_meta)?;
            require_tls_unique(connection_meta)?;
            let prefer_async = prefers_async_response(&request);
            let body = collect_request_body(request, state.config.max_request_body_bytes).await?;
            handle_server_keygen(state, connection_meta, &body, prefer_async).await
        }
        _ => Ok(error_response(
            StatusCode::NOT_FOUND,
            "unknown EST endpoint",
            None,
        )),
    }
}

async fn collect_request_body(
    request: Request<Incoming>,
    max_request_body_bytes: usize,
) -> Result<Vec<u8>> {
    let collected = request
        .into_body()
        .collect()
        .await
        .context("failed to read HTTP request body")?;
    let bytes = collected.to_bytes();

    if bytes.len() > max_request_body_bytes {
        return Err(HttpStatusError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "request body exceeded maximum supported size of {max_request_body_bytes} bytes"
            ),
        )
        .into());
    }

    Ok(bytes.to_vec())
}

fn require_content_type(request: &Request<Incoming>, expected: &str) -> Result<()> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            HttpStatusError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "missing Content-Type header",
            )
        })?;

    if !content_type.starts_with(expected) {
        return Err(HttpStatusError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("invalid Content-Type `{content_type}`, expected `{expected}`"),
        )
        .into());
    }

    Ok(())
}

async fn handle_cacerts(state: &EstState) -> Result<Response<Body>> {
    let pkcs7 = build_certs_only_pkcs7(&state.openssl_binary, &[&state.ca_certificate_path])?;
    Ok(pkcs7_response(pkcs7))
}

async fn handle_simple_enroll(
    state: &EstState,
    connection_meta: &ConnectionMeta,
    body: &[u8],
    reenroll: bool,
    prefer_async: bool,
) -> Result<Response<Body>> {
    ensure_pkcs10_request(body)?;

    let operation = if reenroll {
        "simplereenroll"
    } else {
        "simpleenroll"
    };

    let request = X509Req::from_der(body).map_err(|_| {
        HttpStatusError::new(StatusCode::BAD_REQUEST, "failed to parse PKCS#10 CSR")
    })?;
    let request_public_key = request.public_key().map_err(|_| {
        HttpStatusError::new(StatusCode::BAD_REQUEST, "failed to extract CSR public key")
    })?;
    if !request.verify(&request_public_key).map_err(|_| {
        HttpStatusError::new(StatusCode::BAD_REQUEST, "failed to verify CSR signature")
    })? {
        return Err(HttpStatusError::new(
            StatusCode::BAD_REQUEST,
            "CSR signature verification failed",
        )
        .into());
    }

    if reenroll {
        let peer_certificate = connection_meta.peer_certificate.as_ref().ok_or_else(|| {
            HttpStatusError::new(
                StatusCode::FORBIDDEN,
                "peer certificate is required for reenrollment",
            )
        })?;
        ensure_same_subject_and_alt_name(&state.openssl_binary, &request, peer_certificate)?;
    }

    let context = build_enrollment_request_context(
        &state.openssl_binary,
        operation,
        body,
        &request,
        &request_public_key,
        connection_meta,
    )?;
    let pending_dir = Path::new(&state.config.pending_enrollment_dir);

    if let Some(record) = load_pending_enrollment(pending_dir, operation, &context.artifact_id)? {
        match record.state {
            PendingEnrollmentState::Pending
                if matches!(record.action, EnrollmentAction::Manual) =>
            {
                return Ok(accepted_response(
                    "enrollment request accepted for manual authorization",
                    record.retry_after_seconds,
                ));
            }
            PendingEnrollmentState::Pending => {
                remove_pending_enrollment(pending_dir, operation, &context.artifact_id)?;
            }
            PendingEnrollmentState::Rejected => {
                return Err(HttpStatusError::new(
                    StatusCode::FORBIDDEN,
                    record
                        .reject_reason
                        .unwrap_or_else(|| "enrollment request was rejected".to_owned()),
                )
                .into());
            }
            PendingEnrollmentState::Approved => {
                remove_pending_enrollment(pending_dir, operation, &context.artifact_id)?;
            }
        }
    } else {
        let decision = evaluate_enrollment_policy(&state.config.enrollment, &context)?;
        match decision.action {
            EnrollmentAction::Reject => {
                return Err(HttpStatusError::new(
                    StatusCode::FORBIDDEN,
                    decision
                        .reject_reason
                        .unwrap_or_else(|| "enrollment request rejected by policy".to_owned()),
                )
                .into());
            }
            EnrollmentAction::Manual => {
                persist_pending_enrollment(
                    &state.openssl_binary,
                    pending_dir,
                    &context,
                    &decision,
                    state.config.default_retry_after_seconds,
                    body,
                )?;
                return Ok(accepted_response(
                    "enrollment request accepted for manual authorization",
                    state.config.default_retry_after_seconds,
                ));
            }
            EnrollmentAction::Auto if prefer_async => {
                persist_pending_enrollment(
                    &state.openssl_binary,
                    pending_dir,
                    &context,
                    &decision,
                    state.config.default_retry_after_seconds,
                    body,
                )?;
                return Ok(accepted_response(
                    "enrollment request accepted for delayed processing",
                    state.config.default_retry_after_seconds,
                ));
            }
            EnrollmentAction::Auto => {}
        }
    }

    let issued_certificate = issue_certificate_from_request(
        &state.ca_certificate,
        &state.ca_private_key,
        &request,
        &request_public_key,
    )?;
    let issued_certificate_pem = issued_certificate
        .to_pem()
        .context("failed to serialize issued certificate")?;

    let (stored_csr_path, stored_cert_path) = persist_enrollment_artifacts(
        Path::new(&state.config.enrollment_storage_dir),
        operation,
        body,
        &issued_certificate_pem,
    )?;
    validate_persisted_artifacts_for_csr(
        &state.openssl_binary,
        &stored_csr_path,
        &stored_cert_path,
        &state.ca_certificate_path,
    )?;

    let temp_cert_path = write_temp_file("est-issued", "crt", &issued_certificate_pem)?;
    let result = build_certs_only_pkcs7(
        &state.openssl_binary,
        &[&temp_cert_path, &state.ca_certificate_path],
    );
    cleanup_temp_file(&temp_cert_path);

    Ok(pkcs7_response(result?))
}

async fn handle_server_keygen(
    state: &EstState,
    connection_meta: &ConnectionMeta,
    body: &[u8],
    prefer_async: bool,
) -> Result<Response<Body>> {
    ensure_pkcs10_request(body)?;

    let operation = "serverkeygen";
    let request = X509Req::from_der(body).map_err(|_| {
        HttpStatusError::new(StatusCode::BAD_REQUEST, "failed to parse PKCS#10 CSR")
    })?;
    let request_public_key = request.public_key().map_err(|_| {
        HttpStatusError::new(StatusCode::BAD_REQUEST, "failed to extract CSR public key")
    })?;
    if !request.verify(&request_public_key).map_err(|_| {
        HttpStatusError::new(StatusCode::BAD_REQUEST, "failed to verify CSR signature")
    })? {
        return Err(HttpStatusError::new(
            StatusCode::BAD_REQUEST,
            "CSR signature verification failed",
        )
        .into());
    }

    let context = build_enrollment_request_context(
        &state.openssl_binary,
        operation,
        body,
        &request,
        &request_public_key,
        connection_meta,
    )?;
    let pending_dir = Path::new(&state.config.pending_enrollment_dir);

    if let Some(record) = load_pending_enrollment(pending_dir, operation, &context.artifact_id)? {
        match record.state {
            PendingEnrollmentState::Pending
                if matches!(record.action, EnrollmentAction::Manual) =>
            {
                return Ok(accepted_response(
                    "server-side key generation request accepted for manual authorization",
                    record.retry_after_seconds,
                ));
            }
            PendingEnrollmentState::Pending => {
                remove_pending_enrollment(pending_dir, operation, &context.artifact_id)?;
            }
            PendingEnrollmentState::Rejected => {
                return Err(HttpStatusError::new(
                    StatusCode::FORBIDDEN,
                    record.reject_reason.unwrap_or_else(|| {
                        "server-side key generation request was rejected".to_owned()
                    }),
                )
                .into());
            }
            PendingEnrollmentState::Approved => {
                remove_pending_enrollment(pending_dir, operation, &context.artifact_id)?;
            }
        }
    } else {
        let decision = evaluate_enrollment_policy(&state.config.enrollment, &context)?;
        match decision.action {
            EnrollmentAction::Reject => {
                return Err(HttpStatusError::new(
                    StatusCode::FORBIDDEN,
                    decision.reject_reason.unwrap_or_else(|| {
                        "server-side key generation request rejected by policy".to_owned()
                    }),
                )
                .into());
            }
            EnrollmentAction::Manual => {
                persist_pending_enrollment(
                    &state.openssl_binary,
                    pending_dir,
                    &context,
                    &decision,
                    state.config.default_retry_after_seconds,
                    body,
                )?;
                return Ok(accepted_response(
                    "server-side key generation request accepted for manual authorization",
                    state.config.default_retry_after_seconds,
                ));
            }
            EnrollmentAction::Auto if prefer_async => {
                persist_pending_enrollment(
                    &state.openssl_binary,
                    pending_dir,
                    &context,
                    &decision,
                    state.config.default_retry_after_seconds,
                    body,
                )?;
                return Ok(accepted_response(
                    "server-side key generation request accepted for delayed processing",
                    state.config.default_retry_after_seconds,
                ));
            }
            EnrollmentAction::Auto => {}
        }
    }

    let private_key_path = generate_server_key(&state.openssl_binary, &state.config.key_type)?;
    let private_key_pem = fs::read(&private_key_path).with_context(|| {
        format!(
            "failed to read generated key `{}`",
            private_key_path.display()
        )
    })?;
    let private_key =
        PKey::private_key_from_pem(&private_key_pem).context("failed to parse generated key")?;

    let issued_certificate = issue_certificate_from_request(
        &state.ca_certificate,
        &state.ca_private_key,
        &request,
        &private_key,
    )?;
    let issued_certificate_pem = issued_certificate
        .to_pem()
        .context("failed to serialize issued certificate")?;

    let (stored_csr_path, stored_cert_path) = persist_enrollment_artifacts(
        Path::new(&state.config.enrollment_storage_dir),
        operation,
        body,
        &issued_certificate_pem,
    )?;
    validate_persisted_artifacts_for_private_key(
        &state.openssl_binary,
        &stored_csr_path,
        &stored_cert_path,
        &state.ca_certificate_path,
        &private_key_path,
    )?;

    let cert_path = write_temp_file("est-serverkeygen-cert", "crt", &issued_certificate_pem)?;
    let pkcs7_cert = build_certs_only_pkcs7(
        &state.openssl_binary,
        &[&cert_path, &state.ca_certificate_path],
    )?;

    let peer_certificate = connection_meta.peer_certificate.as_ref().ok_or_else(|| {
        HttpStatusError::new(
            StatusCode::FORBIDDEN,
            "peer certificate is required for serverkeygen encryption",
        )
    })?;
    let peer_certificate_path =
        write_temp_file("est-serverkeygen-peer", "crt", &peer_certificate.to_pem()?)?;
    let encrypted_key = encrypt_private_key_for_recipient(
        &state.openssl_binary,
        &private_key_path,
        &peer_certificate_path,
    )?;

    cleanup_temp_file(&cert_path);
    cleanup_temp_file(&peer_certificate_path);
    cleanup_temp_file(&private_key_path);

    Ok(multipart_serverkeygen_response(pkcs7_cert, encrypted_key))
}

fn require_peer_certificate(connection_meta: &ConnectionMeta) -> Result<()> {
    if connection_meta.peer_certificate.is_none() {
        return Err(HttpStatusError::new(
            StatusCode::FORBIDDEN,
            "EST enrollment operations require a mutually authenticated TLS client certificate",
        )
        .into());
    }

    Ok(())
}

fn require_tls_unique(connection_meta: &ConnectionMeta) -> Result<()> {
    if connection_meta.tls_unique.is_empty() {
        return Err(HttpStatusError::new(
            StatusCode::FORBIDDEN,
            "tls-unique proof-of-possession binding is unavailable for this connection",
        )
        .into());
    }

    Ok(())
}

fn ensure_pkcs10_request(body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(
            HttpStatusError::new(StatusCode::BAD_REQUEST, "empty PKCS#10 request body").into(),
        );
    }

    Ok(())
}

fn ensure_same_subject_and_alt_name(
    openssl_binary: &str,
    request: &X509Req,
    peer_certificate: &X509,
) -> Result<()> {
    let request_subject = request
        .subject_name()
        .to_der()
        .context("failed to serialize request subject")?;
    let peer_subject = peer_certificate
        .subject_name()
        .to_der()
        .context("failed to serialize peer certificate subject")?;

    if request_subject != peer_subject {
        return Err(HttpStatusError::new(
            StatusCode::BAD_REQUEST,
            "simplereenroll requires the same subject as the current client certificate",
        )
        .into());
    }

    let request_sans = extract_subject_alt_names_from_csr(openssl_binary, request)?;
    let peer_sans = extract_subject_alt_names_from_certificate(openssl_binary, peer_certificate)?;

    if request_sans != peer_sans {
        return Err(HttpStatusError::new(
            StatusCode::BAD_REQUEST,
            "simplereenroll requires the same subjectAltName as the current client certificate",
        )
        .into());
    }

    Ok(())
}

fn build_enrollment_request_context(
    openssl_binary: &str,
    operation: &str,
    body: &[u8],
    request: &X509Req,
    request_public_key: &PKey<impl openssl::pkey::HasPublic>,
    connection_meta: &ConnectionMeta,
) -> Result<EnrollmentRequestContext> {
    let subject_cn = first_subject_entry(request.subject_name(), Nid::COMMONNAME)?;
    let subject_ou = first_subject_entry(request.subject_name(), Nid::ORGANIZATIONALUNITNAME)?;
    let subject_o = first_subject_entry(request.subject_name(), Nid::ORGANIZATIONNAME)?;

    let san_entries = extract_subject_alt_names_from_csr(openssl_binary, request)?;
    let san_dns = san_entries
        .iter()
        .filter_map(|value| value.strip_prefix("DNS:").map(ToOwned::to_owned))
        .collect();
    let san_email = san_entries
        .iter()
        .filter_map(|value| value.strip_prefix("email:").map(ToOwned::to_owned))
        .collect();

    let client_cert_issuer = connection_meta
        .peer_certificate
        .as_ref()
        .and_then(|certificate| x509_name_to_string(certificate.issuer_name()).ok());

    Ok(EnrollmentRequestContext {
        operation: operation.to_owned(),
        artifact_id: sha256_hex(body),
        subject_cn,
        subject_ou,
        subject_o,
        san_dns,
        san_email,
        client_cert_issuer,
        key_type: public_key_type_label(request_public_key),
    })
}

fn evaluate_enrollment_policy(
    config: &EnrollmentConfig,
    context: &EnrollmentRequestContext,
) -> Result<EnrollmentDecision> {
    for rule in &config.rules {
        if rule_matches_context(rule, context)? {
            return Ok(EnrollmentDecision {
                action: rule.action.clone(),
                matched_rule_name: (!rule.name.trim().is_empty()).then(|| rule.name.clone()),
                reject_reason: rule.reject_reason.clone(),
            });
        }
    }

    Ok(EnrollmentDecision {
        action: config.default_action.clone(),
        matched_rule_name: None,
        reject_reason: None,
    })
}

fn rule_matches_context(rule: &EnrollmentRule, context: &EnrollmentRequestContext) -> Result<bool> {
    if let Some(pattern) = &rule.match_subject_cn {
        if !optional_regex_match(pattern, context.subject_cn.as_deref())? {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.match_subject_ou {
        if !optional_regex_match(pattern, context.subject_ou.as_deref())? {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.match_subject_o {
        if !optional_regex_match(pattern, context.subject_o.as_deref())? {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.match_client_cert_issuer {
        if !optional_regex_match(pattern, context.client_cert_issuer.as_deref())? {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.match_san_dns {
        if !vector_regex_match(pattern, &context.san_dns)? {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.match_san_email {
        if !vector_regex_match(pattern, &context.san_email)? {
            return Ok(false);
        }
    }
    if let Some(expected_key_type) = &rule.match_key_type {
        if !expected_key_type.eq_ignore_ascii_case(&context.key_type) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn optional_regex_match(pattern: &str, value: Option<&str>) -> Result<bool> {
    let regex = Regex::new(pattern)
        .with_context(|| format!("invalid enrollment authorization regex `{pattern}`"))?;
    Ok(value.is_some_and(|candidate| regex.is_match(candidate)))
}

fn vector_regex_match(pattern: &str, values: &[String]) -> Result<bool> {
    let regex = Regex::new(pattern)
        .with_context(|| format!("invalid enrollment authorization regex `{pattern}`"))?;
    Ok(values.iter().any(|value| regex.is_match(value)))
}

fn first_subject_entry(name: &X509NameRef, nid: Nid) -> Result<Option<String>> {
    name.entries_by_nid(nid)
        .next()
        .map(|entry| {
            entry
                .data()
                .as_utf8()
                .map(|value| value.to_string())
                .context("failed to decode X.509 name entry as UTF-8")
        })
        .transpose()
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

    Ok(parts.join(","))
}

fn public_key_type_label<T>(public_key: &PKey<T>) -> String
where
    T: openssl::pkey::HasPublic,
{
    match public_key.id() {
        PKeyId::RSA => "rsa".to_owned(),
        PKeyId::EC => "ecdsa".to_owned(),
        PKeyId::ED25519 => "ed25519".to_owned(),
        PKeyId::ED448 => "ed448".to_owned(),
        _ => format!("{:?}", public_key.id()).to_ascii_lowercase(),
    }
}

fn pending_record_path(
    pending_enrollment_dir: &Path,
    operation: &str,
    artifact_id: &str,
) -> PathBuf {
    pending_enrollment_dir
        .join(operation)
        .join(artifact_id)
        .join("status.json")
}

fn persist_pending_enrollment(
    openssl_binary: &str,
    pending_enrollment_dir: &Path,
    context: &EnrollmentRequestContext,
    decision: &EnrollmentDecision,
    retry_after_seconds: u32,
    body: &[u8],
) -> Result<()> {
    let pending_dir = pending_enrollment_dir
        .join(&context.operation)
        .join(&context.artifact_id);

    fs::create_dir_all(&pending_dir).with_context(|| {
        format!(
            "failed to create pending request dir `{}`",
            pending_dir.display()
        )
    })?;

    let csr_path = pending_dir.join("request.csr.der");
    fs::write(&csr_path, body)
        .with_context(|| format!("failed to write pending CSR `{}`", csr_path.display()))?;
    validate_stored_csr(openssl_binary, &csr_path)?;

    let record = PendingEnrollmentRecord {
        operation: context.operation.clone(),
        artifact_id: context.artifact_id.clone(),
        retry_after_seconds,
        state: PendingEnrollmentState::Pending,
        matched_rule_name: decision.matched_rule_name.clone(),
        action: decision.action.clone(),
        reject_reason: decision.reject_reason.clone(),
        context: context.clone(),
    };

    let record_path = pending_record_path(
        pending_enrollment_dir,
        &context.operation,
        &context.artifact_id,
    );
    let record_json = serde_json::to_vec_pretty(&record)
        .context("failed to serialize pending enrollment record")?;
    fs::write(&record_path, record_json)
        .with_context(|| format!("failed to write pending record `{}`", record_path.display()))?;

    Ok(())
}

fn load_pending_enrollment(
    pending_enrollment_dir: &Path,
    operation: &str,
    artifact_id: &str,
) -> Result<Option<PendingEnrollmentRecord>> {
    let record_path = pending_record_path(pending_enrollment_dir, operation, artifact_id);
    if !record_path.exists() {
        return Ok(None);
    }

    let content = fs::read(&record_path)
        .with_context(|| format!("failed to read pending record `{}`", record_path.display()))?;
    let record = serde_json::from_slice(&content)
        .with_context(|| format!("failed to parse pending record `{}`", record_path.display()))?;
    Ok(Some(record))
}

fn write_pending_enrollment(
    pending_enrollment_dir: &Path,
    record: &PendingEnrollmentRecord,
) -> Result<()> {
    let record_path = pending_record_path(
        pending_enrollment_dir,
        &record.operation,
        &record.artifact_id,
    );
    let content = serde_json::to_vec_pretty(record)
        .context("failed to serialize pending enrollment record")?;
    fs::write(&record_path, content)
        .with_context(|| format!("failed to write pending record `{}`", record_path.display()))?;
    Ok(())
}

fn remove_pending_enrollment(
    pending_enrollment_dir: &Path,
    operation: &str,
    artifact_id: &str,
) -> Result<()> {
    let pending_dir = pending_enrollment_dir.join(operation).join(artifact_id);
    if pending_dir.exists() {
        fs::remove_dir_all(&pending_dir).with_context(|| {
            format!(
                "failed to remove pending request `{}`",
                pending_dir.display()
            )
        })?;
    }
    Ok(())
}

pub fn list_pending_enrollments(
    pending_enrollment_dir: &Path,
) -> Result<Vec<PendingEnrollmentRecord>> {
    let mut records = Vec::new();

    if !pending_enrollment_dir.exists() {
        return Ok(records);
    }

    for operation_entry in fs::read_dir(pending_enrollment_dir)
        .with_context(|| format!("failed to read `{}`", pending_enrollment_dir.display()))?
    {
        let operation_entry = operation_entry?;
        if !operation_entry.file_type()?.is_dir() {
            continue;
        }

        for artifact_entry in fs::read_dir(operation_entry.path())
            .with_context(|| format!("failed to read `{}`", operation_entry.path().display()))?
        {
            let artifact_entry = artifact_entry?;
            if !artifact_entry.file_type()?.is_dir() {
                continue;
            }

            let record_path = artifact_entry.path().join("status.json");
            if !record_path.exists() {
                continue;
            }

            let content = fs::read(&record_path).with_context(|| {
                format!("failed to read pending record `{}`", record_path.display())
            })?;
            let record: PendingEnrollmentRecord =
                serde_json::from_slice(&content).with_context(|| {
                    format!("failed to parse pending record `{}`", record_path.display())
                })?;
            records.push(record);
        }
    }

    records.sort_by(|left, right| {
        left.operation
            .cmp(&right.operation)
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });

    Ok(records)
}

pub fn update_pending_enrollment_state(
    pending_enrollment_dir: &Path,
    operation: &str,
    artifact_id: &str,
    state: PendingEnrollmentState,
    reject_reason: Option<String>,
) -> Result<PendingEnrollmentRecord> {
    let mut record = load_pending_enrollment(pending_enrollment_dir, operation, artifact_id)?
        .ok_or_else(|| {
            anyhow::anyhow!("pending enrollment `{operation}/{artifact_id}` was not found")
        })?;

    record.state = state;
    record.reject_reason = reject_reason;
    write_pending_enrollment(pending_enrollment_dir, &record)?;

    Ok(record)
}

pub fn list_enrollment_artifacts(
    enrollment_storage_dir: &Path,
) -> Result<Vec<EnrollmentArtifactSummary>> {
    let mut artifacts = Vec::new();

    if !enrollment_storage_dir.exists() {
        return Ok(artifacts);
    }

    for operation_entry in fs::read_dir(enrollment_storage_dir)
        .with_context(|| format!("failed to read `{}`", enrollment_storage_dir.display()))?
    {
        let operation_entry = operation_entry?;
        if !operation_entry.file_type()?.is_dir() {
            continue;
        }

        let operation = operation_entry.file_name().to_string_lossy().into_owned();

        for artifact_entry in fs::read_dir(operation_entry.path())
            .with_context(|| format!("failed to read `{}`", operation_entry.path().display()))?
        {
            let artifact_entry = artifact_entry?;
            if !artifact_entry.file_type()?.is_dir() {
                continue;
            }

            let artifact_path = artifact_entry.path();
            let artifact_id = artifact_entry.file_name().to_string_lossy().into_owned();
            let csr_path = artifact_path.join("request.csr.der");
            let certificate_path = artifact_path.join("issued-cert.pem");

            artifacts.push(EnrollmentArtifactSummary {
                operation: operation.clone(),
                artifact_id,
                csr_path: csr_path.to_string_lossy().into_owned(),
                certificate_path: certificate_path
                    .exists()
                    .then(|| certificate_path.to_string_lossy().into_owned()),
            });
        }
    }

    artifacts.sort_by(|left, right| {
        left.operation
            .cmp(&right.operation)
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });

    Ok(artifacts)
}

fn issue_certificate_from_request<T>(
    ca_certificate: &X509,
    ca_private_key: &PKey<Private>,
    request: &X509Req,
    public_key: &PKey<T>,
) -> Result<X509>
where
    T: openssl::pkey::HasPublic,
{
    let mut builder = X509::builder().context("failed to create X509 builder")?;
    builder
        .set_version(2)
        .context("failed to set X509 version")?;

    let serial_bn =
        BigNum::from_u32(next_serial_number()).context("failed to create serial number")?;
    let serial = Asn1Integer::from_bn(&serial_bn).context("failed to encode serial number")?;
    builder
        .set_serial_number(&serial)
        .context("failed to set serial number")?;
    builder
        .set_subject_name(request.subject_name())
        .context("failed to set subject name")?;
    builder
        .set_issuer_name(ca_certificate.subject_name())
        .context("failed to set issuer name")?;
    builder
        .set_pubkey(public_key)
        .context("failed to set certificate public key")?;

    let not_before = Asn1Time::days_from_now(0).context("failed to create notBefore")?;
    let not_after = Asn1Time::days_from_now(365).context("failed to create notAfter")?;
    builder
        .set_not_before(&not_before)
        .context("failed to set notBefore")?;
    builder
        .set_not_after(&not_after)
        .context("failed to set notAfter")?;

    let basic_constraints = BasicConstraints::new()
        .critical()
        .build()
        .context("failed to add basic constraints")?;
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .context("failed to add key usage")?;
    let ext_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .build()
        .context("failed to add extended key usage")?;

    builder
        .append_extension(basic_constraints)
        .context("failed to append basic constraints")?;
    builder
        .append_extension(key_usage)
        .context("failed to append key usage")?;
    builder
        .append_extension(ext_key_usage)
        .context("failed to append extended key usage")?;

    builder
        .sign(ca_private_key, MessageDigest::sha256())
        .context("failed to sign issued certificate")?;

    Ok(builder.build())
}

fn build_certs_only_pkcs7(openssl_binary: &str, certificate_paths: &[&Path]) -> Result<Vec<u8>> {
    let mut command = Command::new(openssl_binary);
    command.arg("crl2pkcs7").arg("-nocrl");

    for path in certificate_paths {
        command.arg("-certfile").arg(path);
    }

    command.arg("-outform").arg("DER");

    let output = command
        .output()
        .with_context(|| format!("failed to execute `{openssl_binary} crl2pkcs7`"))?;

    if !output.status.success() {
        bail!(
            "`{openssl_binary} crl2pkcs7` failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(output.stdout)
}

fn encrypt_private_key_for_recipient(
    openssl_binary: &str,
    private_key_path: &Path,
    recipient_certificate_path: &Path,
) -> Result<Vec<u8>> {
    let output_path = write_temp_file("est-serverkeygen-encrypted", "der", &[])?;
    let output = Command::new(openssl_binary)
        .args([
            "cms",
            "-encrypt",
            "-binary",
            "-outform",
            "DER",
            "-aes-256-cbc",
            "-in",
        ])
        .arg(private_key_path)
        .args(["-recip"])
        .arg(recipient_certificate_path)
        .args(["-out"])
        .arg(&output_path)
        .output()
        .with_context(|| format!("failed to execute `{openssl_binary} cms -encrypt`"))?;

    if !output.status.success() {
        cleanup_temp_file(&output_path);
        bail!(
            "`{openssl_binary} cms -encrypt` failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let encrypted = fs::read(&output_path)
        .with_context(|| format!("failed to read encrypted key `{}`", output_path.display()))?;
    cleanup_temp_file(&output_path);
    Ok(encrypted)
}

fn generate_server_key(openssl_binary: &str, key_type: &str) -> Result<PathBuf> {
    let output_path = temp_path("est-serverkeygen-key", "pem");
    let mut command = Command::new(openssl_binary);
    command.arg("genpkey");

    match key_type {
        "rsa2048" => {
            command.args(["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]);
        }
        "rsa3072" => {
            command.args(["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"]);
        }
        "rsa4096" => {
            command.args(["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"]);
        }
        "ecdsa-p256" => {
            command.args([
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
            ]);
        }
        "ecdsa-p384" => {
            command.args([
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:secp384r1",
            ]);
        }
        "ml-dsa65" => {
            command.args(["-algorithm", "ML-DSA-65"]);
        }
        "ml-dsa87" => {
            command.args(["-algorithm", "ML-DSA-87"]);
        }
        _ => {
            command.args(["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]);
        }
    }

    command.arg("-out").arg(&output_path);

    let output = command
        .output()
        .with_context(|| format!("failed to execute `{openssl_binary} genpkey`"))?;

    if !output.status.success() {
        bail!(
            "`{openssl_binary} genpkey` failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(output_path)
}

fn prefers_async_response(request: &Request<Incoming>) -> bool {
    request
        .headers()
        .get(PREFER_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_ascii_lowercase())
                .any(|item| item == RESPOND_ASYNC_PREFERENCE)
        })
        .unwrap_or(false)
}

fn persist_enrollment_artifacts(
    enrollment_storage_dir: &Path,
    operation: &str,
    csr_der: &[u8],
    issued_certificate_pem: &[u8],
) -> Result<(PathBuf, PathBuf)> {
    let artifact_dir = enrollment_storage_dir
        .join(operation)
        .join(sha256_hex(csr_der));

    fs::create_dir_all(&artifact_dir).with_context(|| {
        format!(
            "failed to create enrollment dir `{}`",
            artifact_dir.display()
        )
    })?;

    let csr_path = artifact_dir.join("request.csr.der");
    let cert_path = artifact_dir.join("issued-cert.pem");

    fs::write(&csr_path, csr_der)
        .with_context(|| format!("failed to write stored CSR `{}`", csr_path.display()))?;
    fs::write(&cert_path, issued_certificate_pem).with_context(|| {
        format!(
            "failed to write stored certificate `{}`",
            cert_path.display()
        )
    })?;
    fs::write(
        artifact_dir.join("metadata.txt"),
        format!(
            "operation={operation}\nartifact_id={}\n",
            sha256_hex(csr_der)
        ),
    )
    .with_context(|| format!("failed to write metadata for `{}`", artifact_dir.display()))?;

    Ok((csr_path, cert_path))
}

fn validate_persisted_artifacts_for_csr(
    openssl_binary: &str,
    csr_path: &Path,
    cert_path: &Path,
    ca_certificate_path: &Path,
) -> Result<()> {
    validate_stored_csr(openssl_binary, csr_path)?;
    validate_stored_certificate(openssl_binary, cert_path, ca_certificate_path)?;
    let csr_public_key = extract_public_key_from_csr(openssl_binary, csr_path)?;
    let cert_public_key = extract_public_key_from_certificate(openssl_binary, cert_path)?;
    if csr_public_key != cert_public_key {
        bail!(
            "issued certificate `{}` does not match stored CSR public key `{}`",
            cert_path.display(),
            csr_path.display()
        );
    }

    Ok(())
}

fn validate_persisted_artifacts_for_private_key(
    openssl_binary: &str,
    csr_path: &Path,
    cert_path: &Path,
    ca_certificate_path: &Path,
    private_key_path: &Path,
) -> Result<()> {
    validate_stored_csr(openssl_binary, csr_path)?;
    validate_stored_certificate(openssl_binary, cert_path, ca_certificate_path)?;
    let cert_public_key = extract_public_key_from_certificate(openssl_binary, cert_path)?;
    let private_key_public_key =
        extract_public_key_from_private_key(openssl_binary, private_key_path)?;
    if cert_public_key != private_key_public_key {
        bail!(
            "issued certificate `{}` does not match generated private key `{}`",
            cert_path.display(),
            private_key_path.display()
        );
    }

    Ok(())
}

fn validate_stored_csr(openssl_binary: &str, csr_path: &Path) -> Result<()> {
    run_command(
        openssl_binary,
        &[
            "req",
            "-inform",
            "DER",
            "-in",
            csr_path.to_string_lossy().as_ref(),
            "-verify",
            "-noout",
        ],
    )
    .with_context(|| format!("failed to validate stored CSR `{}`", csr_path.display()))?;

    Ok(())
}

fn validate_stored_certificate(
    openssl_binary: &str,
    cert_path: &Path,
    ca_certificate_path: &Path,
) -> Result<()> {
    run_command(
        openssl_binary,
        &[
            "x509",
            "-in",
            cert_path.to_string_lossy().as_ref(),
            "-noout",
            "-subject",
            "-issuer",
        ],
    )
    .with_context(|| {
        format!(
            "failed to inspect stored certificate `{}`",
            cert_path.display()
        )
    })?;

    run_command(
        openssl_binary,
        &[
            "verify",
            "-CAfile",
            ca_certificate_path.to_string_lossy().as_ref(),
            cert_path.to_string_lossy().as_ref(),
        ],
    )
    .with_context(|| {
        format!(
            "failed to verify stored certificate `{}`",
            cert_path.display()
        )
    })?;

    Ok(())
}

fn extract_public_key_from_csr(openssl_binary: &str, csr_path: &Path) -> Result<String> {
    run_command(
        openssl_binary,
        &[
            "req",
            "-inform",
            "DER",
            "-in",
            csr_path.to_string_lossy().as_ref(),
            "-pubkey",
            "-noout",
        ],
    )
    .with_context(|| {
        format!(
            "failed to extract public key from CSR `{}`",
            csr_path.display()
        )
    })
}

fn extract_public_key_from_certificate(openssl_binary: &str, cert_path: &Path) -> Result<String> {
    run_command(
        openssl_binary,
        &[
            "x509",
            "-in",
            cert_path.to_string_lossy().as_ref(),
            "-pubkey",
            "-noout",
        ],
    )
    .with_context(|| {
        format!(
            "failed to extract public key from certificate `{}`",
            cert_path.display()
        )
    })
}

fn extract_public_key_from_private_key(openssl_binary: &str, key_path: &Path) -> Result<String> {
    run_command(
        openssl_binary,
        &[
            "pkey",
            "-in",
            key_path.to_string_lossy().as_ref(),
            "-pubout",
            "-outform",
            "PEM",
        ],
    )
    .with_context(|| {
        format!(
            "failed to extract public key from private key `{}`",
            key_path.display()
        )
    })
}

fn extract_subject_alt_names_from_csr(
    openssl_binary: &str,
    request: &X509Req,
) -> Result<BTreeSet<String>> {
    let request_path = write_temp_file("est-reenroll-request", "pem", &request.to_pem()?)?;
    let output = run_command(
        openssl_binary,
        &[
            "req",
            "-in",
            request_path.to_string_lossy().as_ref(),
            "-noout",
            "-text",
        ],
    )
    .with_context(|| format!("failed to inspect CSR `{}`", request_path.display()))?;
    cleanup_temp_file(&request_path);

    Ok(parse_subject_alt_names_from_text(&output))
}

fn extract_subject_alt_names_from_certificate(
    openssl_binary: &str,
    certificate: &X509,
) -> Result<BTreeSet<String>> {
    let certificate_path = write_temp_file(
        "est-reenroll-peer-certificate",
        "pem",
        &certificate.to_pem()?,
    )?;
    let output = run_command(
        openssl_binary,
        &[
            "x509",
            "-in",
            certificate_path.to_string_lossy().as_ref(),
            "-noout",
            "-text",
        ],
    )
    .with_context(|| {
        format!(
            "failed to inspect certificate `{}`",
            certificate_path.display()
        )
    })?;
    cleanup_temp_file(&certificate_path);

    Ok(parse_subject_alt_names_from_text(&output))
}

fn parse_subject_alt_names_from_text(text: &str) -> BTreeSet<String> {
    let mut entries = BTreeSet::new();
    let mut in_san_section = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.contains("Subject Alternative Name") {
            in_san_section = true;
            continue;
        }

        if !in_san_section {
            continue;
        }

        if trimmed.is_empty() {
            break;
        }

        if !line.starts_with(' ') && !line.starts_with('\t') {
            break;
        }

        for item in trimmed.split(',') {
            let normalized = item.trim().replace("IP Address:", "IP:");
            if !normalized.is_empty() {
                entries.insert(normalized);
            }
        }
    }

    entries
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = sha256(input);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn write_temp_file(prefix: &str, extension: &str, content: &[u8]) -> Result<PathBuf> {
    let path = temp_path(prefix, extension);
    fs::write(&path, content)
        .with_context(|| format!("failed to write temporary file `{}`", path.display()))?;
    Ok(path)
}

fn temp_path(prefix: &str, extension: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!("{prefix}-{stamp}.{extension}"))
}

fn cleanup_temp_file(path: &Path) {
    let _ = fs::remove_file(path);
}

fn next_serial_number() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(1);

    (now % u32::MAX as u64) as u32
}

fn pkcs7_response(pkcs7: Vec<u8>) -> Response<Body> {
    binary_response(
        StatusCode::OK,
        "application/pkcs7-mime; smime-type=certs-only",
        pkcs7,
    )
}

fn multipart_serverkeygen_response(pkcs7_cert: Vec<u8>, encrypted_key: Vec<u8>) -> Response<Body> {
    let boundary = "est-serverkeygen-boundary";
    let mut body = Vec::new();

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Type: application/pkcs7-mime; smime-type=certs-only\r\nContent-Transfer-Encoding: binary\r\n\r\n",
    );
    body.extend_from_slice(&pkcs7_cert);
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Type: application/pkcs7-mime\r\nContent-Transfer-Encoding: binary\r\n\r\n",
    );
    body.extend_from_slice(&encrypted_key);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        format!("multipart/mixed; boundary={boundary}")
            .parse()
            .expect("static multipart content type"),
    );
    response.headers_mut().insert(
        HeaderName::from_static(CONTENT_TRANSFER_ENCODING_HEADER),
        "binary".parse().expect("static binary encoding"),
    );
    response
}

fn binary_response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        content_type.parse().expect("static content type"),
    );
    response.headers_mut().insert(
        HeaderName::from_static(CONTENT_TRANSFER_ENCODING_HEADER),
        "binary".parse().expect("static binary encoding"),
    );
    response
}

fn accepted_response(message: &str, retry_after: u32) -> Response<Body> {
    let mut response = Response::new(Body::from(message.to_owned()));
    *response.status_mut() = StatusCode::ACCEPTED;
    response.headers_mut().insert(
        CONTENT_TYPE,
        "text/plain; charset=utf-8"
            .parse()
            .expect("static plain text content type"),
    );
    response.headers_mut().insert(
        RETRY_AFTER,
        retry_after
            .to_string()
            .parse()
            .expect("static retry-after header"),
    );
    response
}

fn error_response(status: StatusCode, message: &str, retry_after: Option<u32>) -> Response<Body> {
    let mut response = Response::new(Body::from(message.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        "text/plain; charset=utf-8"
            .parse()
            .expect("static plain text content type"),
    );

    if let Some(retry_after) = retry_after {
        response.headers_mut().insert(
            RETRY_AFTER,
            retry_after
                .to_string()
                .parse()
                .expect("static retry-after header"),
        );
    }

    response
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
