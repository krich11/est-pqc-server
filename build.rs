use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    let openssl_version = detect_openssl_version().unwrap_or_else(|error| {
        panic!("failed to detect system OpenSSL version: {error}");
    });

    if !openssl_version.starts_with("OpenSSL 3.") {
        panic!(
            "OpenSSL 3.x is required, detected `{openssl_version}`. Install system OpenSSL 3 and set OPENSSL_DIR accordingly"
        );
    }

    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        let lib_dir = PathBuf::from(&openssl_dir).join("lib");
        let include_dir = PathBuf::from(&openssl_dir).join("include");

        if lib_dir.exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        }

        if include_dir.exists() {
            println!("cargo:include={}", include_dir.display());
        }
    }

    if let Ok(lib_dir) = env::var("OPENSSL_LIB_DIR") {
        println!("cargo:rustc-link-search=native={lib_dir}");
    }

    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
}

fn detect_openssl_version() -> Result<String, String> {
    if let Ok(openssl_bin) = env::var("OPENSSL") {
        return run_openssl_version(&openssl_bin);
    }

    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        let candidate = PathBuf::from(openssl_dir).join("bin").join("openssl");
        if candidate.exists() {
            return run_openssl_version(candidate.to_string_lossy().as_ref());
        }
    }

    run_openssl_version("openssl")
}

fn run_openssl_version(openssl_bin: &str) -> Result<String, String> {
    let output = Command::new(openssl_bin)
        .arg("version")
        .output()
        .map_err(|error| format!("could not execute `{openssl_bin} version`: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "`{openssl_bin} version` failed with status {}",
            output.status
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("openssl version output was not valid UTF-8: {error}"))?;

    Ok(stdout.trim().to_owned())
}
