use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr64BE;
use rand::TryRngCore;
use rand::rngs::OsRng;
use rpassword::read_password;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use argon2::Argon2;
use serde::Deserialize;
use base64::prelude::*;
use chrono::prelude::*;
use zeroize::Zeroize;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256Ctr = Ctr64BE<Aes256>;

/// These two constants are fixed salts used in the rounds
/// of Argon2 hashing of the key material.
const MAGIC: &[u8] = b"789c33a8303536333437323334b328353301001ccc0395";
const ENCHA: &[u8] = b"789c33a8303132733337373335732d353301001df903be";

/// The Config struct is required, parsed from enchantress.toml.
#[derive(Deserialize)]
struct Config {
    ciphertext_hash: String,
}

/// Write a config file each time we encrypt to enchantress.toml.
fn write_config(ciphertext_path: &str, ciphertext_hash: &str) -> io::Result<()> {
    let readi: DateTime<Utc> = Utc::now();
    let config_content = format!(
        r#"ciphertext_path = "{}"
ciphertext_hash = "{}"
creation_time = "{}"
"#,
        ciphertext_path, ciphertext_hash, readi
        );
    let mut file = File::create("./enchantress.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchantress.toml: {}", e)))?;
    file.write_all(config_content.as_bytes())?;
    Ok(())
}

/// Ensure that the ciphertext hasn't been tampered with and that the key material is correct.
fn checks(validate: &str, ciphertext_hash: &str) -> bool {
    let result = validate == ciphertext_hash;
    if result == true {
      return true
    } else {
      println!("Ciphertext and/or password are not as expected. \
        The supplied password was wrong, the enchantress.toml was wrong, or the file was tampered with.");
      println!("Found hash: {}", validate);
      println!("Expected hash: {}", ciphertext_hash);
      return false
    };
}

/// Generate key material based on the password, nonce, and then
/// hash the hash by mixing two fixed values.
fn a2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    let mut rkm = [0u8; 32];
    let _ = Argon2::default().hash_password_into(password, salt, &mut okm);
    let _ = Argon2::default().hash_password_into(ENCHA, &okm,  &mut rkm);
    rkm
}

/// Use a SHA3 XOF to hash the ciphertext for integrity checking.
fn ciphertext_hash(password: &[u8], file_data: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(password);
    hasher.update(file_data);
    let mut reader = hasher.finalize_xof();
    let mut key = vec![0u8; length];
    XofReader::read(&mut reader, &mut key);
    key
}

/// Generate a timestamp + random nonce.
fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp_nanos = now.as_nanos();
    nonce[0..8].copy_from_slice(&timestamp_nanos.to_le_bytes()[0..8]);
    let _ = OsRng.try_fill_bytes(&mut nonce[8..16]);
    nonce
}

/// Encrypt a file with AES-256 in CTR mode.
fn encrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let nonce = generate_nonce();
    let mut cipher = Aes256Ctr::new(key.into(), &nonce.into());
    cipher.apply_keystream(&mut data);

    let mut output = File::create(output_file)?;
    output.write_all(&nonce)?;
    output.write_all(&data)?;

    Ok(())
}

/// Decrypt a file with AES-256 in CTR mode.
fn decrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut nonce = [0u8; 16];
    file.read_exact(&mut nonce)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let mut cipher = Aes256Ctr::new(key.into(), &nonce.into());
    cipher.apply_keystream(&mut data);

    let mut output = File::create(output_file)?;
    output.write_all(&data)?;

    Ok(())
}

/// Decrypt a file to STDOUT in AES-256 in CTR mode.
fn decrypt_stdout(input_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut nonce = [0u8; 16];
    file.read_exact(&mut nonce)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let mut cipher = Aes256Ctr::new(key.into(), &nonce.into());
    cipher.apply_keystream(&mut data);

    println!("{}", String::from_utf8_lossy(&data).to_string());

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <input_file> <output_file> < -d, -e, -ee, -do, -de, -deo>", args[0]);
        process::exit(1);
    }

    let input_file = &args[1];
    let output_file = &args[2];
    let flag = &args[3];

    match flag.as_str() {
        "-deo" => {
            let mut file = File::open("./enchantress.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchantress.toml: {}", e)))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchantress.toml: {}", e)))?;
            let config: Config = toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchantress.toml: {}", e)))?;
            let mut file = File::open(input_file)?;
            let mut nonce = [0u8; 16];
            file.read_exact(&mut nonce)?;
            let strpassword = env::var("ENC").expect("ENC env var not set");
            let password = strpassword.as_bytes();
            let mut key = a2(password, &MAGIC);
            let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file: {}", e)))?;
            let mut input_file_data = Vec::new();
            in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)))?;
            let validate = ciphertext_hash(&key, &input_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            let checkme = &validate_str;
            if checks(checkme, &config.ciphertext_hash) == true {
              decrypt_stdout(input_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?;
            } else {
              println!("Refusing to decrypt.");
            };
            key.zeroize();
        },
        "-do" => {
            let mut file = File::open("./enchantress.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchantress.toml: {}", e)))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchantress.toml: {}", e)))?;
            let config: Config = toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchantress.toml: {}", e)))?;
            let mut file = File::open(input_file)?;
            let mut nonce = [0u8; 16];
            file.read_exact(&mut nonce)?;
            print!("Enter password: ");
            std::io::stdout().flush()?;
            let password = read_password()?;
            let bpassword = password.as_bytes();
            let mut key = a2(bpassword, &MAGIC);
            let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file: {}", e)))?;
            let mut input_file_data = Vec::new();
            in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)))?;
            let validate = ciphertext_hash(&key, &input_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            let checkme = &validate_str;
            if checks(checkme, &config.ciphertext_hash) == true {
              decrypt_stdout(input_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?;
            } else {
              println!("Refusing to decrypt.");
            };
            key.zeroize();
        },
        "-de" => {
            let mut file = File::open("./enchantress.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchantress.toml: {}", e)))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchantress.toml: {}", e)))?;
            let config: Config = toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchantress.toml: {}", e)))?;
            let mut file = File::open(input_file)?;
            let mut nonce = [0u8; 16];
            file.read_exact(&mut nonce)?;
            let strpassword = env::var("ENC").expect("ENC env var not set");
            let password = strpassword.as_bytes();
            let mut key = a2(password, &MAGIC);
            let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file: {}", e)))?;
            let mut input_file_data = Vec::new();
            in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)))?;
            let validate = ciphertext_hash(&key, &input_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            let checkme = &validate_str;
            if checks(checkme, &config.ciphertext_hash) == true {
              decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?;
            } else {
              println!("Refusing to decrypt.");
            };
            key.zeroize();
        },
        "-d" => {
            let mut file = File::open("./enchantress.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchantress.toml: {}", e)))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchantress.toml: {}", e)))?;
            let config: Config = toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchantress.toml: {}", e)))?;
            let mut file = File::open(input_file)?;
            let mut nonce = [0u8; 16];
            file.read_exact(&mut nonce)?;
            print!("Enter password: ");
            std::io::stdout().flush()?;
            let password = read_password()?;
            let bpassword = password.as_bytes();
            let mut key = a2(bpassword, &MAGIC);
            let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file: {}", e)))?;
            let mut input_file_data = Vec::new();
            in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)))?;
            let validate = ciphertext_hash(&key, &input_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            let checkme = &validate_str;
            if checks(checkme, &config.ciphertext_hash) == true {
              decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?;
            } else {
              println!("Refusing to decrypt.");
            };
            key.zeroize();
        },
        "-ee" => {
            let password = env::var("ENC").expect("ENC env var not set");
            let bpassword = password.as_bytes();
            let mut key = a2(bpassword, &MAGIC);
            encrypt_file(input_file, output_file, &key)?;
            let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file: {}", e)))?;
            let mut output_file_data = Vec::new();
            out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)))?;
            let validate = ciphertext_hash(&key, &output_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            println!("Validation string is: {validate_str}");
            let _ = write_config(output_file, &validate_str);
            key.zeroize();
        },
        "-e" => {
            print!("Enter password: ");
            std::io::stdout().flush()?;
            let password = read_password()?;
            let bpassword = password.as_bytes();
            let mut key = a2(bpassword, &MAGIC);
            encrypt_file(input_file, output_file, &key)?;
            let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file: {}", e)))?;
            let mut output_file_data = Vec::new();
            out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)))?;
            let validate = ciphertext_hash(&key, &output_file_data, 64);
            let validate_str = BASE64_STANDARD.encode(&validate);
            println!("Validation string is: {validate_str}");
            let _ = write_config(output_file, &validate_str);
            key.zeroize();
        },

        _ => {
            eprintln!("Invalid flag. Use -d for decryption or -e for encryption of a file using a supplied password. Use -ee to encrypt with an environment variable ENC, and -de to decrypt with an environment variable. Use -do to decrypt to STDOUT, and -deo to use an environment variable and decrypt to STDOUT. ");
            process::exit(1);
        }
    }

    Ok(())
}
