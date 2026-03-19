use anyhow::{anyhow, Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use clap::Parser;
use openssl::rand::rand_bytes;

#[derive(Debug, Parser)]
#[command(
    name = "hash-webui-password",
    version,
    about = "Generate an Argon2 hash for WebUI basic authentication"
)]
struct Cli {
    #[arg(long, help = "Plaintext password to hash")]
    password: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut salt_bytes = [0_u8; 16];
    rand_bytes(&mut salt_bytes).context("failed to generate password salt")?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|error| anyhow!("failed to encode password salt: {error}"))?;

    let hash = Argon2::default()
        .hash_password(cli.password.as_bytes(), &salt)
        .map_err(|error| anyhow!("failed to hash password: {error}"))?;

    println!("{}", hash);

    Ok(())
}
