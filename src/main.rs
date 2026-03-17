mod est;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use crossterm::{
    event, execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    env, fmt,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DEFAULT_OPENSSL_DIR: &str = "/opt/homebrew/opt/openssl@3.5";
const DEFAULT_CONFIG_PATH: &str = "config.toml";
const DEFAULT_LOG_PATH: &str = "logs/env-check.log";
const TLS_VERSION: &str = "TLS1.3";

const TLS_CIPHER_SUITES: [&str; 3] = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
];

#[derive(Debug, Parser)]
#[command(
    name = "est-server",
    version,
    about = "EST server bootstrap, configuration tool, and runtime entrypoint"
)]
struct Cli {
    #[arg(long, help = "Launch configuration mode")]
    config_mode: bool,

    #[arg(
        long,
        default_value = DEFAULT_CONFIG_PATH,
        help = "Configuration file path for reading or writing"
    )]
    config: PathBuf,

    #[arg(long, help = "Override bind address")]
    listen_address: Option<String>,

    #[arg(long, help = "Override bind port")]
    listen_port: Option<u16>,

    #[arg(long, help = "Override TLS version")]
    tls_version: Option<String>,

    #[arg(long, help = "Override preferred TLS 1.3 cipher suite")]
    preferred_tls_cipher_suite: Option<String>,

    #[arg(long, help = "Override server-side key generation key type")]
    key_type: Option<String>,

    #[arg(long, help = "Override FIPS enablement with true or false")]
    enable_fips: Option<bool>,

    #[arg(long, help = "Override OpenSSL installation directory")]
    openssl_dir: Option<String>,

    #[arg(long, help = "Override OpenSSL CLI binary path")]
    openssl_binary: Option<String>,

    #[arg(long, help = "Override issuing CA certificate path")]
    ca_certificate_path: Option<String>,

    #[arg(long, help = "Override issuing CA private key path")]
    ca_private_key_path: Option<String>,

    #[arg(long, help = "Override client-auth trust anchor path")]
    client_auth_ca_certificate_path: Option<String>,

    #[arg(long, help = "Override TLS server certificate path")]
    tls_certificate_path: Option<String>,

    #[arg(long, help = "Override TLS server private key path")]
    tls_private_key_path: Option<String>,

    #[arg(long, help = "Override enrollment storage directory")]
    enrollment_storage_dir: Option<String>,

    #[arg(long, help = "Override pending-enrollment storage directory")]
    pending_enrollment_dir: Option<String>,

    #[arg(long, help = "Override maximum accepted HTTP request body size in bytes")]
    max_request_body_bytes: Option<usize>,

    #[arg(long, help = "Override default Retry-After value in seconds")]
    default_retry_after_seconds: Option<u32>,

    #[arg(long, help = "Override detected ML-KEM support with true or false")]
    ml_kem_supported: Option<bool>,

    #[arg(long, help = "Override detected ML-DSA support with true or false")]
    ml_dsa_supported: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    MlDsa65,
    MlDsa87,
}

impl KeyType {
    fn labels() -> &'static [&'static str] {
        &[
            "RSA 2048",
            "RSA 3072",
            "RSA 4096",
            "ECDSA P-256",
            "ECDSA P-384",
            "ML-DSA-65",
            "ML-DSA-87",
        ]
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Rsa2048,
            1 => Self::Rsa3072,
            2 => Self::Rsa4096,
            3 => Self::EcdsaP256,
            4 => Self::EcdsaP384,
            5 => Self::MlDsa65,
            6 => Self::MlDsa87,
            _ => Self::EcdsaP256,
        }
    }

    fn default_for(report: &EnvironmentReport) -> Self {
        if report.ml_dsa_supported {
            Self::MlDsa65
        } else {
            Self::EcdsaP256
        }
    }

    fn index(&self) -> usize {
        match self {
            Self::Rsa2048 => 0,
            Self::Rsa3072 => 1,
            Self::Rsa4096 => 2,
            Self::EcdsaP256 => 3,
            Self::EcdsaP384 => 4,
            Self::MlDsa65 => 5,
            Self::MlDsa87 => 6,
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Rsa2048 => "RSA 2048",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
            Self::EcdsaP256 => "ECDSA P-256",
            Self::EcdsaP384 => "ECDSA P-384",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        };

        f.write_str(value)
    }
}

#[derive(Debug, Clone)]
struct EnvironmentReport {
    runtime_openssl_version: String,
    cli_openssl_version: String,
    openssl_binary: String,
    openssl_dir: String,
    architecture: String,
    operating_system: String,
    pkg_config_available: bool,
    fips_requested: bool,
    fips_available: bool,
    ml_kem_supported: bool,
    ml_dsa_supported: bool,
    kem_algorithms: Vec<String>,
    signature_algorithms: Vec<String>,
    providers: Vec<String>,
    library_paths_present: Vec<String>,
    issues: Vec<String>,
    recommendations: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.config_mode {
        ensure_runtime_directories().context("failed to prepare runtime directories")?;
        init_logging().context("failed to initialize logging")?;
        return est::run_server_with_overrides(&cli.config, &cli.server_overrides()).await;
    }

    ensure_bootstrap_directories().context("failed to prepare bootstrap directories")?;
    init_logging().context("failed to initialize logging")?;

    let report = detect_environment().context("failed to detect environment")?;
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();

    if interactive {
        render_summary_tui(&report)?;
    }

    let mut config = if interactive {
        prompt_for_configuration(&report)?
    } else {
        default_configuration(&report)
    };

    apply_cli_overrides_to_config(&mut config, &cli.server_overrides());

    write_config(&cli.config, &config).context("failed to write configuration file")?;
    append_environment_log(&report, &config).context("failed to write env-check log")?;

    println!("Configuration written to {}", cli.config.display());
    println!("Environment log written to {}", DEFAULT_LOG_PATH);
    println!(
        "OpenSSL runtime version: {}",
        report.runtime_openssl_version
    );
    println!("OpenSSL CLI version: {}", report.cli_openssl_version);
    println!("FIPS available: {}", yes_no(report.fips_available));
    println!("ML-KEM supported: {}", yes_no(report.ml_kem_supported));
    println!("ML-DSA supported: {}", yes_no(report.ml_dsa_supported));

    if !report.issues.is_empty() {
        println!();
        println!("Detected issues:");
        for issue in &report.issues {
            println!("- {issue}");
        }
    }

    if !report.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for recommendation in &report.recommendations {
            println!("- {recommendation}");
        }
    }

    Ok(())
}

impl Cli {
    fn server_overrides(&self) -> est::ServerConfigOverrides {
        est::ServerConfigOverrides {
            listen_address: self.listen_address.clone(),
            listen_port: self.listen_port,
            tls_version: self.tls_version.clone(),
            preferred_tls_cipher_suite: self.preferred_tls_cipher_suite.clone(),
            key_type: self.key_type.clone(),
            enable_fips: self.enable_fips,
            openssl_dir: self.openssl_dir.clone(),
            openssl_binary: self.openssl_binary.clone(),
            ca_certificate_path: self.ca_certificate_path.clone(),
            ca_private_key_path: self.ca_private_key_path.clone(),
            client_auth_ca_certificate_path: self.client_auth_ca_certificate_path.clone(),
            tls_certificate_path: self.tls_certificate_path.clone(),
            tls_private_key_path: self.tls_private_key_path.clone(),
            enrollment_storage_dir: self.enrollment_storage_dir.clone(),
            pending_enrollment_dir: self.pending_enrollment_dir.clone(),
            max_request_body_bytes: self.max_request_body_bytes,
            default_retry_after_seconds: self.default_retry_after_seconds,
            ml_kem_supported: self.ml_kem_supported,
            ml_dsa_supported: self.ml_dsa_supported,
        }
    }
}

fn ensure_bootstrap_directories() -> Result<()> {
    for path in [
        "src/bin",
        "src/config",
        "src/est",
        "demo",
        "logs",
        ".github/workflows",
        "memory-bank",
    ] {
        fs::create_dir_all(path).with_context(|| format!("failed to create `{path}`"))?;
    }

    Ok(())
}

fn ensure_runtime_directories() -> Result<()> {
    for path in ["logs", "demo"] {
        fs::create_dir_all(path).with_context(|| format!("failed to create `{path}`"))?;
    }

    Ok(())
}

fn init_logging() -> Result<()> {
    let _file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DEFAULT_LOG_PATH)
        .with_context(|| format!("failed to open `{DEFAULT_LOG_PATH}`"))?;

    Ok(())
}

fn detect_environment() -> Result<EnvironmentReport> {
    let runtime_openssl_version = openssl::version::version().to_owned();
    if !runtime_openssl_version.starts_with("OpenSSL 3.") {
        bail!("OpenSSL 3.x is required at runtime, detected `{runtime_openssl_version}`");
    }

    let openssl_dir = detect_openssl_dir();
    let openssl_binary = detect_openssl_binary(&openssl_dir)?;
    let cli_openssl_version = run_command(&openssl_binary, &["version"])
        .with_context(|| format!("failed to query `{openssl_binary} version`"))?;

    if !cli_openssl_version.starts_with("OpenSSL 3.") {
        bail!("OpenSSL 3.x is required from the CLI, detected `{cli_openssl_version}`");
    }

    let providers_output = run_command(&openssl_binary, &["list", "-providers"]).unwrap_or_default();
    let kem_output = run_command(&openssl_binary, &["list", "-kem-algorithms"]).unwrap_or_default();
    let signature_output =
        run_command(&openssl_binary, &["list", "-signature-algorithms"]).unwrap_or_default();

    let providers = collect_meaningful_lines(&providers_output);
    let kem_algorithms = collect_meaningful_lines(&kem_output);
    let signature_algorithms = collect_meaningful_lines(&signature_output);

    let fips_requested = env::var("OPENSSL_FIPS").ok().as_deref() == Some("1")
        || env::var("OPENSSL_CONF")
            .map(|value| value.to_ascii_lowercase().contains("fips"))
            .unwrap_or(false);

    let fips_available = providers
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("fips"));

    let ml_kem_supported = kem_algorithms
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("ml-kem"));

    let ml_dsa_supported = signature_algorithms
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("ml-dsa"));

    let pkg_config_available = Command::new("pkg-config")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    let library_paths_present = detect_library_paths(&openssl_dir);

    let mut issues = Vec::new();
    let mut recommendations = Vec::new();

    if !pkg_config_available {
        push_unique(
            &mut issues,
            "pkg-config not detected; openssl-sys may fail to discover system OpenSSL".to_owned(),
        );
        push_unique(
            &mut recommendations,
            "Install pkg-config and export PKG_CONFIG_PATH to the system OpenSSL pkgconfig directory"
                .to_owned(),
        );
    }

    if !runtime_openssl_version.contains("3.") {
        push_unique(
            &mut issues,
            format!("unsupported runtime OpenSSL version detected: {runtime_openssl_version}"),
        );
    }

    if !cli_openssl_version.contains("3.") {
        push_unique(
            &mut issues,
            format!("unsupported CLI OpenSSL version detected: {cli_openssl_version}"),
        );
    }

    if !fips_available {
        push_unique(
            &mut issues,
            "OpenSSL FIPS provider is not currently available".to_owned(),
        );
        push_unique(
            &mut recommendations,
            "On Linux, install the OpenSSL FIPS provider package and configure OPENSSL_CONF to load the fips provider".to_owned(),
        );
        push_unique(
            &mut recommendations,
            "On RHEL or Fedora, run `sudo fips-mode-setup --enable` and ensure OpenSSL 3 FIPS modules are installed".to_owned(),
        );
        push_unique(
            &mut recommendations,
            "On Debian or Ubuntu, install `openssl-fips-provider` if available and configure `/etc/ssl/openssl.cnf` to activate it".to_owned(),
        );
    }

    if fips_requested && !fips_available {
        push_unique(
            &mut issues,
            "FIPS mode was requested but no FIPS provider was detected".to_owned(),
        );
    }

    if !ml_kem_supported {
        push_unique(
            &mut issues,
            "ML-KEM algorithms were not detected in the system OpenSSL provider set".to_owned(),
        );
        push_unique(
            &mut recommendations,
            "Upgrade to OpenSSL 3.2+ or install a provider that exposes ML-KEM hybrids".to_owned(),
        );
    }

    if !ml_dsa_supported {
        push_unique(
            &mut issues,
            "ML-DSA algorithms were not detected in the system OpenSSL provider set".to_owned(),
        );
        push_unique(
            &mut recommendations,
            "Upgrade to OpenSSL 3.5+ or install a provider that exposes ML-DSA-65 and ML-DSA-87"
                .to_owned(),
        );
    }

    if !library_paths_present.iter().any(|path| path.contains("libssl")) {
        push_unique(
            &mut issues,
            "system libssl library path was not detected under the configured OpenSSL directory"
                .to_owned(),
        );
        push_unique(
            &mut recommendations,
            format!("Verify that `{openssl_dir}` points to the system OpenSSL 3 installation"),
        );
    }

    if env::consts::OS != "linux" {
        push_unique(
            &mut issues,
            format!(
                "current platform is `{}`; final RPM packaging target remains Linux only",
                env::consts::OS
            ),
        );
        push_unique(
            &mut recommendations,
            "Use the generated configuration for development on this host, then build and package the final EST server on Linux".to_owned(),
        );
    }

    push_unique(
        &mut recommendations,
        format!(
            "Export OPENSSL_DIR={openssl_dir} and PKG_CONFIG_PATH={openssl_dir}/lib/pkgconfig before release builds"
        ),
    );

    Ok(EnvironmentReport {
        runtime_openssl_version,
        cli_openssl_version,
        openssl_binary,
        openssl_dir,
        architecture: env::consts::ARCH.to_owned(),
        operating_system: env::consts::OS.to_owned(),
        pkg_config_available,
        fips_requested,
        fips_available,
        ml_kem_supported,
        ml_dsa_supported,
        kem_algorithms,
        signature_algorithms,
        providers,
        library_paths_present,
        issues,
        recommendations,
    })
}

fn detect_openssl_dir() -> String {
    if let Ok(value) = env::var("OPENSSL_DIR") {
        return value;
    }

    DEFAULT_OPENSSL_DIR.to_owned()
}

fn detect_openssl_binary(openssl_dir: &str) -> Result<String> {
    if let Ok(value) = env::var("OPENSSL") {
        return Ok(value);
    }

    let configured = Path::new(openssl_dir).join("bin").join("openssl");
    if configured.exists() {
        return Ok(configured.to_string_lossy().into_owned());
    }

    Ok("openssl".to_owned())
}

fn run_command(binary: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute `{binary}`"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "`{binary} {}` exited with status {}",
            args.join(" "),
            output.status
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("`{binary}` output was not valid UTF-8"))?;

    Ok(stdout.trim().to_owned())
}

fn collect_meaningful_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn detect_library_paths(openssl_dir: &str) -> Vec<String> {
    let lib_dir = PathBuf::from(openssl_dir).join("lib");
    let candidates = [
        lib_dir.join("libssl.so.3"),
        lib_dir.join("libcrypto.so.3"),
        lib_dir.join("libssl.3.dylib"),
        lib_dir.join("libcrypto.3.dylib"),
        lib_dir.join("libssl.dylib"),
        lib_dir.join("libcrypto.dylib"),
    ];

    candidates
        .iter()
        .filter(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

fn render_summary_tui(report: &EnvironmentReport) -> Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode().context("failed to enable raw mode")?;
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal UI")?;

    let content = [
        format!("Runtime OpenSSL: {}", report.runtime_openssl_version),
        format!("CLI OpenSSL: {}", report.cli_openssl_version),
        format!("OpenSSL binary: {}", report.openssl_binary),
        format!("OpenSSL dir: {}", report.openssl_dir),
        format!("Architecture: {}", report.architecture),
        format!("Operating system: {}", report.operating_system),
        format!("FIPS available: {}", yes_no(report.fips_available)),
        format!("ML-KEM supported: {}", yes_no(report.ml_kem_supported)),
        format!("ML-DSA supported: {}", yes_no(report.ml_dsa_supported)),
        format!("Detected issues: {}", report.issues.len()),
        "Press any key to continue to configuration prompts".to_owned(),
    ]
    .join("\n");

    let draw_result = terminal.draw(|frame| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .split(frame.area());

        let header = Paragraph::new("EST Server Bootstrap")
            .block(Block::default().borders(Borders::ALL).title("Summary"));

        let body = Paragraph::new(content.as_str())
            .block(Block::default().borders(Borders::ALL).title("Environment"))
            .wrap(Wrap { trim: true });

        let footer = Paragraph::new("dialoguer + ratatui configuration mode")
            .block(Block::default().borders(Borders::ALL).title("Mode"));

        frame.render_widget(header, chunks[0]);
        frame.render_widget(body, chunks[1]);
        frame.render_widget(footer, chunks[2]);
    });

    let poll_result = event::poll(Duration::from_secs(30));

    let cleanup_result = (|| -> Result<()> {
        disable_raw_mode().context("failed to disable raw mode")?;
        let mut stdout = io::stdout();
        execute!(stdout, LeaveAlternateScreen).context("failed to leave alternate screen")?;
        Ok(())
    })();

    draw_result.context("failed to render terminal UI")?;
    let _ = poll_result;
    cleanup_result?;

    Ok(())
}

fn prompt_for_configuration(report: &EnvironmentReport) -> Result<est::ServerConfig> {
    let theme = ColorfulTheme::default();
    let default_key_type = KeyType::default_for(report);
    let key_type_index = Select::with_theme(&theme)
        .with_prompt("Select EST server key type")
        .items(KeyType::labels())
        .default(default_key_type.index())
        .interact()
        .context("failed to select key type")?;

    let cipher_index = Select::with_theme(&theme)
        .with_prompt("Select preferred TLS 1.3 cipher suite")
        .items(&TLS_CIPHER_SUITES)
        .default(0)
        .interact()
        .context("failed to select TLS cipher suite")?;

    let listen_address = Input::with_theme(&theme)
        .with_prompt("Enter listening address")
        .default("0.0.0.0".to_owned())
        .interact_text()
        .context("failed to read listening address")?;

    let listen_port = Input::with_theme(&theme)
        .with_prompt("Enter listening port")
        .default(8443_u16)
        .interact_text()
        .context("failed to read listening port")?;

    let ca_certificate_path = Input::with_theme(&theme)
        .with_prompt("Enter issuing CA certificate path")
        .default("demo/demo-ca.crt".to_owned())
        .interact_text()
        .context("failed to read CA certificate path")?;

    let ca_private_key_path = Input::with_theme(&theme)
        .with_prompt("Enter issuing CA private key path")
        .default("demo/demo-ca.key".to_owned())
        .interact_text()
        .context("failed to read CA private key path")?;

    let client_auth_ca_certificate_path = Input::with_theme(&theme)
        .with_prompt("Enter client-auth CA certificate path")
        .default("demo/demo-ca.crt".to_owned())
        .interact_text()
        .context("failed to read client-auth CA certificate path")?;

    let tls_certificate_path = Input::with_theme(&theme)
        .with_prompt("Enter TLS server certificate path")
        .default("demo/rsa-2048-server.crt".to_owned())
        .interact_text()
        .context("failed to read TLS certificate path")?;

    let tls_private_key_path = Input::with_theme(&theme)
        .with_prompt("Enter TLS server private key path")
        .default("demo/rsa-2048-server.key".to_owned())
        .interact_text()
        .context("failed to read TLS private key path")?;

    let enrollment_storage_dir = Input::with_theme(&theme)
        .with_prompt("Enter enrollment storage directory")
        .default("logs/enrollments".to_owned())
        .interact_text()
        .context("failed to read enrollment storage directory")?;

    let pending_enrollment_dir = Input::with_theme(&theme)
        .with_prompt("Enter pending enrollment storage directory")
        .default("logs/pending".to_owned())
        .interact_text()
        .context("failed to read pending enrollment storage directory")?;

    let max_request_body_bytes = Input::with_theme(&theme)
        .with_prompt("Enter maximum request body size in bytes")
        .default(1024_usize * 1024)
        .interact_text()
        .context("failed to read maximum request body size")?;

    let default_retry_after_seconds = Input::with_theme(&theme)
        .with_prompt("Enter default Retry-After value in seconds")
        .default(60_u32)
        .interact_text()
        .context("failed to read Retry-After value")?;

    let enable_fips = if report.fips_available {
        Confirm::with_theme(&theme)
            .with_prompt("Enable FIPS mode")
            .default(report.fips_requested)
            .interact()
            .context("failed to read FIPS mode selection")?
    } else {
        false
    };

    Ok(est::ServerConfig {
        listen_address,
        listen_port,
        tls_version: TLS_VERSION.to_owned(),
        preferred_tls_cipher_suite: TLS_CIPHER_SUITES[cipher_index].to_owned(),
        key_type: key_type_to_config_value(KeyType::from_index(key_type_index)),
        enable_fips,
        openssl_dir: report.openssl_dir.clone(),
        openssl_binary: report.openssl_binary.clone(),
        ca_certificate_path,
        ca_private_key_path,
        client_auth_ca_certificate_path,
        tls_certificate_path,
        tls_private_key_path,
        enrollment_storage_dir,
        pending_enrollment_dir,
        max_request_body_bytes,
        default_retry_after_seconds,
        ml_kem_supported: report.ml_kem_supported,
        ml_dsa_supported: report.ml_dsa_supported,
    })
}

fn default_configuration(report: &EnvironmentReport) -> est::ServerConfig {
    est::ServerConfig {
        listen_address: "0.0.0.0".to_owned(),
        listen_port: 8443,
        tls_version: TLS_VERSION.to_owned(),
        preferred_tls_cipher_suite: TLS_CIPHER_SUITES[0].to_owned(),
        key_type: key_type_to_config_value(KeyType::default_for(report)),
        enable_fips: false,
        openssl_dir: report.openssl_dir.clone(),
        openssl_binary: report.openssl_binary.clone(),
        ca_certificate_path: "demo/demo-ca.crt".to_owned(),
        ca_private_key_path: "demo/demo-ca.key".to_owned(),
        client_auth_ca_certificate_path: "demo/demo-ca.crt".to_owned(),
        tls_certificate_path: "demo/rsa-2048-server.crt".to_owned(),
        tls_private_key_path: "demo/rsa-2048-server.key".to_owned(),
        enrollment_storage_dir: "logs/enrollments".to_owned(),
        pending_enrollment_dir: "logs/pending".to_owned(),
        max_request_body_bytes: 1024 * 1024,
        default_retry_after_seconds: 60,
        ml_kem_supported: report.ml_kem_supported,
        ml_dsa_supported: report.ml_dsa_supported,
    }
}

fn apply_cli_overrides_to_config(
    config: &mut est::ServerConfig,
    overrides: &est::ServerConfigOverrides,
) {
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
}

fn key_type_to_config_value(key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa2048 => "rsa2048",
        KeyType::Rsa3072 => "rsa3072",
        KeyType::Rsa4096 => "rsa4096",
        KeyType::EcdsaP256 => "ecdsa-p256",
        KeyType::EcdsaP384 => "ecdsa-p384",
        KeyType::MlDsa65 => "ml-dsa65",
        KeyType::MlDsa87 => "ml-dsa87",
    }
    .to_owned()
}

fn write_config(path: &Path, config: &est::ServerConfig) -> Result<()> {
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory `{}`", parent.display()))?;
    }

    let content = toml::to_string_pretty(config).context("failed to serialize configuration")?;
    fs::write(path, content).with_context(|| format!("failed to write `{}`", path.display()))?;
    Ok(())
}

fn append_environment_log(report: &EnvironmentReport, config: &est::ServerConfig) -> Result<()> {
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DEFAULT_LOG_PATH)
        .with_context(|| format!("failed to open `{DEFAULT_LOG_PATH}`"))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);

    writeln!(
        log_file,
        "=== EST bootstrap environment check @ {timestamp} ==="
    )?;
    writeln!(
        log_file,
        "runtime_openssl_version = {}",
        report.runtime_openssl_version
    )?;
    writeln!(
        log_file,
        "cli_openssl_version = {}",
        report.cli_openssl_version
    )?;
    writeln!(log_file, "openssl_binary = {}", report.openssl_binary)?;
    writeln!(log_file, "openssl_dir = {}", report.openssl_dir)?;
    writeln!(log_file, "architecture = {}", report.architecture)?;
    writeln!(log_file, "operating_system = {}", report.operating_system)?;
    writeln!(
        log_file,
        "pkg_config_available = {}",
        report.pkg_config_available
    )?;
    writeln!(log_file, "fips_requested = {}", report.fips_requested)?;
    writeln!(log_file, "fips_available = {}", report.fips_available)?;
    writeln!(log_file, "ml_kem_supported = {}", report.ml_kem_supported)?;
    writeln!(log_file, "ml_dsa_supported = {}", report.ml_dsa_supported)?;
    writeln!(log_file, "providers = {}", report.providers.join(" | "))?;
    writeln!(
        log_file,
        "kem_algorithms = {}",
        report.kem_algorithms.join(" | ")
    )?;
    writeln!(
        log_file,
        "signature_algorithms = {}",
        report.signature_algorithms.join(" | ")
    )?;
    writeln!(
        log_file,
        "library_paths_present = {}",
        report.library_paths_present.join(" | ")
    )?;
    writeln!(log_file, "issues = {}", report.issues.join(" | "))?;
    writeln!(
        log_file,
        "recommendations = {}",
        report.recommendations.join(" | ")
    )?;
    writeln!(
        log_file,
        "config = {}",
        toml::to_string_pretty(config)?.replace('\n', " ")
    )?;
    writeln!(log_file)?;

    Ok(())
}

fn push_unique(values: &mut Vec<String>, candidate: String) {
    if !values.iter().any(|value| value == &candidate) {
        values.push(candidate);
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}