use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const DEFAULT_CONFIG_PATH: &str = "config.toml";
const DEFAULT_DEMO_DIR: &str = "demo";
const DEFAULT_OPENSSL_DIR: &str = "/opt/homebrew/opt/openssl@3.5";

#[derive(Debug, Default, Deserialize)]
struct BootstrapConfig {
    openssl_binary: Option<String>,
    openssl_dir: Option<String>,
    ml_dsa_supported: Option<bool>,
}

#[derive(Clone, Copy, Debug)]
enum IdentityRole {
    Server,
    Client,
}

impl IdentityRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }

    fn extension_section(self) -> &'static str {
        match self {
            Self::Server => "server_cert",
            Self::Client => "client_cert",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum KeyKind {
    Rsa(u16),
    Ec(&'static str),
    MlDsa(&'static str),
}

#[derive(Clone, Copy, Debug)]
struct DemoProfile {
    slug: &'static str,
    key_kind: KeyKind,
    role: IdentityRole,
    common_name: &'static str,
}

fn main() -> Result<()> {
    let config = load_bootstrap_config()?;
    let openssl_binary = detect_openssl_binary(&config)?;
    let openssl_version = run_command(&openssl_binary, &["version".to_owned()])?;

    if !openssl_version.starts_with("OpenSSL 3.") {
        bail!("OpenSSL 3.x is required, detected `{openssl_version}`");
    }

    let demo_dir = PathBuf::from(DEFAULT_DEMO_DIR);
    fs::create_dir_all(&demo_dir).with_context(|| {
        format!(
            "failed to create demo directory `{}`",
            demo_dir.to_string_lossy()
        )
    })?;

    let ca_ext_path = demo_dir.join("ca-cert-ext.cnf");
    let leaf_ext_path = demo_dir.join("leaf-cert-ext.cnf");
    fs::write(&ca_ext_path, ca_extension_file()).with_context(|| {
        format!(
            "failed to write CA extension file `{}`",
            ca_ext_path.to_string_lossy()
        )
    })?;
    fs::write(&leaf_ext_path, leaf_extension_file()).with_context(|| {
        format!(
            "failed to write leaf extension file `{}`",
            leaf_ext_path.to_string_lossy()
        )
    })?;

    generate_demo_ca(&openssl_binary, &demo_dir, &ca_ext_path)?;
    validate_certificate(
        &openssl_binary,
        &demo_dir.join("demo-ca.crt"),
        None,
        "demo CA certificate",
    )?;

    let profiles = demo_profiles();
    if profiles
        .iter()
        .any(|profile| matches!(profile.key_kind, KeyKind::MlDsa(_)))
        && config.ml_dsa_supported == Some(false)
    {
        bail!("ML-DSA demo artifacts were requested, but config.toml reports `ml_dsa_supported = false`");
    }

    let mut generated_files = Vec::with_capacity(profiles.len() * 3 + 5);

    generated_files.push(demo_dir.join("demo-ca.key"));
    generated_files.push(demo_dir.join("demo-ca.csr"));
    generated_files.push(demo_dir.join("demo-ca.crt"));
    generated_files.push(demo_dir.join("demo-ca.srl"));
    generated_files.push(ca_ext_path.clone());
    generated_files.push(leaf_ext_path.clone());

    for profile in profiles {
        generate_identity(
            &openssl_binary,
            &demo_dir,
            &leaf_ext_path,
            profile,
        )?;
        generated_files.push(demo_dir.join(format!(
            "{}-{}.key",
            profile.slug,
            profile.role.as_str()
        )));
        generated_files.push(demo_dir.join(format!(
            "{}-{}.csr",
            profile.slug,
            profile.role.as_str()
        )));
        generated_files.push(demo_dir.join(format!(
            "{}-{}.crt",
            profile.slug,
            profile.role.as_str()
        )));
    }

    write_validation_report(&demo_dir, &openssl_version, &generated_files)?;

    println!("Generated EST demo key and certificate artifacts in `{DEFAULT_DEMO_DIR}`");
    println!("OpenSSL: {openssl_version}");
    println!("Profiles generated: {}", demo_profiles().len());

    Ok(())
}

fn load_bootstrap_config() -> Result<BootstrapConfig> {
    let config_path = Path::new(DEFAULT_CONFIG_PATH);
    if !config_path.exists() {
        return Ok(BootstrapConfig::default());
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

fn demo_profiles() -> [DemoProfile; 14] {
    [
        DemoProfile {
            slug: "rsa-2048",
            key_kind: KeyKind::Rsa(2048),
            role: IdentityRole::Server,
            common_name: "rsa-2048-server.demo.est",
        },
        DemoProfile {
            slug: "rsa-2048",
            key_kind: KeyKind::Rsa(2048),
            role: IdentityRole::Client,
            common_name: "rsa-2048-client.demo.est",
        },
        DemoProfile {
            slug: "rsa-3072",
            key_kind: KeyKind::Rsa(3072),
            role: IdentityRole::Server,
            common_name: "rsa-3072-server.demo.est",
        },
        DemoProfile {
            slug: "rsa-3072",
            key_kind: KeyKind::Rsa(3072),
            role: IdentityRole::Client,
            common_name: "rsa-3072-client.demo.est",
        },
        DemoProfile {
            slug: "rsa-4096",
            key_kind: KeyKind::Rsa(4096),
            role: IdentityRole::Server,
            common_name: "rsa-4096-server.demo.est",
        },
        DemoProfile {
            slug: "rsa-4096",
            key_kind: KeyKind::Rsa(4096),
            role: IdentityRole::Client,
            common_name: "rsa-4096-client.demo.est",
        },
        DemoProfile {
            slug: "ecdsa-p256",
            key_kind: KeyKind::Ec("prime256v1"),
            role: IdentityRole::Server,
            common_name: "ecdsa-p256-server.demo.est",
        },
        DemoProfile {
            slug: "ecdsa-p256",
            key_kind: KeyKind::Ec("prime256v1"),
            role: IdentityRole::Client,
            common_name: "ecdsa-p256-client.demo.est",
        },
        DemoProfile {
            slug: "ecdsa-p384",
            key_kind: KeyKind::Ec("secp384r1"),
            role: IdentityRole::Server,
            common_name: "ecdsa-p384-server.demo.est",
        },
        DemoProfile {
            slug: "ecdsa-p384",
            key_kind: KeyKind::Ec("secp384r1"),
            role: IdentityRole::Client,
            common_name: "ecdsa-p384-client.demo.est",
        },
        DemoProfile {
            slug: "ml-dsa-65",
            key_kind: KeyKind::MlDsa("ML-DSA-65"),
            role: IdentityRole::Server,
            common_name: "ml-dsa-65-server.demo.est",
        },
        DemoProfile {
            slug: "ml-dsa-65",
            key_kind: KeyKind::MlDsa("ML-DSA-65"),
            role: IdentityRole::Client,
            common_name: "ml-dsa-65-client.demo.est",
        },
        DemoProfile {
            slug: "ml-dsa-87",
            key_kind: KeyKind::MlDsa("ML-DSA-87"),
            role: IdentityRole::Server,
            common_name: "ml-dsa-87-server.demo.est",
        },
        DemoProfile {
            slug: "ml-dsa-87",
            key_kind: KeyKind::MlDsa("ML-DSA-87"),
            role: IdentityRole::Client,
            common_name: "ml-dsa-87-client.demo.est",
        },
    ]
}

fn generate_demo_ca(openssl_binary: &str, demo_dir: &Path, ca_ext_path: &Path) -> Result<()> {
    let ca_key_path = demo_dir.join("demo-ca.key");
    let ca_csr_path = demo_dir.join("demo-ca.csr");
    let ca_crt_path = demo_dir.join("demo-ca.crt");

    generate_private_key(openssl_binary, KeyKind::Rsa(4096), &ca_key_path)?;
    validate_private_key(openssl_binary, &ca_key_path, "demo CA private key")?;

    run_command(
        openssl_binary,
        &[
            "req".to_owned(),
            "-new".to_owned(),
            "-key".to_owned(),
            path_arg(&ca_key_path),
            "-out".to_owned(),
            path_arg(&ca_csr_path),
            "-subj".to_owned(),
            "/CN=EST Demo Root CA".to_owned(),
        ],
    )
    .context("failed to generate demo CA CSR")?;

    run_command(
        openssl_binary,
        &[
            "x509".to_owned(),
            "-req".to_owned(),
            "-in".to_owned(),
            path_arg(&ca_csr_path),
            "-signkey".to_owned(),
            path_arg(&ca_key_path),
            "-out".to_owned(),
            path_arg(&ca_crt_path),
            "-days".to_owned(),
            "3650".to_owned(),
            "-extfile".to_owned(),
            path_arg(ca_ext_path),
            "-extensions".to_owned(),
            "ca_cert".to_owned(),
        ],
    )
    .context("failed to self-sign demo CA certificate")?;

    Ok(())
}

fn generate_identity(
    openssl_binary: &str,
    demo_dir: &Path,
    leaf_ext_path: &Path,
    profile: DemoProfile,
) -> Result<()> {
    let basename = format!("{}-{}", profile.slug, profile.role.as_str());
    let key_path = demo_dir.join(format!("{basename}.key"));
    let csr_path = demo_dir.join(format!("{basename}.csr"));
    let crt_path = demo_dir.join(format!("{basename}.crt"));
    let ca_cert_path = demo_dir.join("demo-ca.crt");
    let ca_key_path = demo_dir.join("demo-ca.key");
    let ca_serial_path = demo_dir.join("demo-ca.srl");

    generate_private_key(openssl_binary, profile.key_kind, &key_path)?;
    validate_private_key(openssl_binary, &key_path, &format!("{basename} private key"))?;

    run_command(
        openssl_binary,
        &[
            "req".to_owned(),
            "-new".to_owned(),
            "-key".to_owned(),
            path_arg(&key_path),
            "-out".to_owned(),
            path_arg(&csr_path),
            "-subj".to_owned(),
            format!("/CN={}", profile.common_name),
        ],
    )
    .with_context(|| format!("failed to generate CSR for `{basename}`"))?;

    let mut sign_args = vec![
        "x509".to_owned(),
        "-req".to_owned(),
        "-in".to_owned(),
        path_arg(&csr_path),
        "-CA".to_owned(),
        path_arg(&ca_cert_path),
        "-CAkey".to_owned(),
        path_arg(&ca_key_path),
        "-out".to_owned(),
        path_arg(&crt_path),
        "-days".to_owned(),
        "825".to_owned(),
        "-extfile".to_owned(),
        path_arg(leaf_ext_path),
        "-extensions".to_owned(),
        profile.role.extension_section().to_owned(),
    ];

    if ca_serial_path.exists() {
        sign_args.push("-CAserial".to_owned());
        sign_args.push(path_arg(&ca_serial_path));
    } else {
        sign_args.push("-CAcreateserial".to_owned());
        sign_args.push("-CAserial".to_owned());
        sign_args.push(path_arg(&ca_serial_path));
    }

    run_command(openssl_binary, &sign_args)
        .with_context(|| format!("failed to sign certificate for `{basename}`"))?;

    validate_certificate(
        openssl_binary,
        &crt_path,
        Some(&ca_cert_path),
        &format!("{basename} certificate"),
    )?;

    Ok(())
}

fn generate_private_key(openssl_binary: &str, kind: KeyKind, output_path: &Path) -> Result<()> {
    let args = match kind {
        KeyKind::Rsa(bits) => vec![
            "genpkey".to_owned(),
            "-algorithm".to_owned(),
            "RSA".to_owned(),
            "-pkeyopt".to_owned(),
            format!("rsa_keygen_bits:{bits}"),
            "-out".to_owned(),
            path_arg(output_path),
        ],
        KeyKind::Ec(curve) => vec![
            "genpkey".to_owned(),
            "-algorithm".to_owned(),
            "EC".to_owned(),
            "-pkeyopt".to_owned(),
            format!("ec_paramgen_curve:{curve}"),
            "-out".to_owned(),
            path_arg(output_path),
        ],
        KeyKind::MlDsa(algorithm) => vec![
            "genpkey".to_owned(),
            "-algorithm".to_owned(),
            algorithm.to_owned(),
            "-out".to_owned(),
            path_arg(output_path),
        ],
    };

    run_command(openssl_binary, &args).with_context(|| {
        format!(
            "failed to generate private key `{}`",
            output_path.to_string_lossy()
        )
    })?;

    Ok(())
}

fn validate_private_key(openssl_binary: &str, key_path: &Path, label: &str) -> Result<()> {
    run_command(
        openssl_binary,
        &[
            "pkey".to_owned(),
            "-in".to_owned(),
            path_arg(key_path),
            "-pubout".to_owned(),
            "-out".to_owned(),
            "/dev/null".to_owned(),
        ],
    )
    .with_context(|| format!("failed to validate {label}"))?;

    Ok(())
}

fn validate_certificate(
    openssl_binary: &str,
    cert_path: &Path,
    ca_cert_path: Option<&Path>,
    label: &str,
) -> Result<()> {
    run_command(
        openssl_binary,
        &[
            "x509".to_owned(),
            "-in".to_owned(),
            path_arg(cert_path),
            "-noout".to_owned(),
            "-subject".to_owned(),
            "-issuer".to_owned(),
        ],
    )
    .with_context(|| format!("failed to inspect {label}"))?;

    if let Some(ca_cert_path) = ca_cert_path {
        run_command(
            openssl_binary,
            &[
                "verify".to_owned(),
                "-CAfile".to_owned(),
                path_arg(ca_cert_path),
                path_arg(cert_path),
            ],
        )
        .with_context(|| format!("failed to verify {label} against demo CA"))?;
    }

    Ok(())
}

fn write_validation_report(
    demo_dir: &Path,
    openssl_version: &str,
    generated_files: &[PathBuf],
) -> Result<()> {
    let report_path = demo_dir.join("validation-report.md");
    let mut lines = Vec::with_capacity(generated_files.len() + 16);

    lines.push("# Demo Validation Report".to_owned());
    lines.push(String::new());
    lines.push(format!("- OpenSSL: {openssl_version}"));
    lines.push("- Status: generated and locally validated".to_owned());
    lines.push("- Profiles: RSA 2048/3072/4096, ECDSA P-256/P-384, ML-DSA-65/87".to_owned());
    lines.push("- Roles: server, client".to_owned());
    lines.push(String::new());
    lines.push("## Generated Files".to_owned());
    lines.push(String::new());

    for path in generated_files {
        lines.push(format!("- {}", path.to_string_lossy()));
    }

    lines.push(String::new());
    lines.push("## Validation Checks".to_owned());
    lines.push(String::new());
    lines.push("- OpenSSL 3.x detected".to_owned());
    lines.push("- Demo CA key and certificate generated".to_owned());
    lines.push("- All private keys parsed with `openssl pkey`".to_owned());
    lines.push("- All leaf certificates parsed with `openssl x509`".to_owned());
    lines.push("- All leaf certificates verified against the demo CA".to_owned());

    fs::write(&report_path, lines.join("\n")).with_context(|| {
        format!(
            "failed to write validation report `{}`",
            report_path.to_string_lossy()
        )
    })?;

    Ok(())
}

fn ca_extension_file() -> &'static str {
    "[ca_cert]
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
"
}

fn leaf_extension_file() -> &'static str {
    "[server_cert]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=@server_alt_names

[server_alt_names]
DNS.1=localhost
IP.1=127.0.0.1

[client_cert]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"
}

fn run_command(binary: &str, args: &[String]) -> Result<String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute `{binary}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "`{binary} {}` failed with status {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("`{binary}` output was not valid UTF-8"))?;

    Ok(stdout.trim().to_owned())
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}