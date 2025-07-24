use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr64BE;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use argon2::Argon2;

use std::fs::File;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256Ctr = Ctr64BE<Aes256>;

/// These two constants are fixed salts used in the rounds
/// of Argon2 hashing of the key material.
#[allow(unused)]
pub const MAGIC: &[u8] = b"789c33a8303536333437323334b328353301001ccc0395";
#[allow(unused)]
const ENCHA: &[u8] = b"789c33a8303132733337373335732d353301001df903be";

/// Ensure that the ciphertext hasn't been tampered with and that the key material is correct.
#[allow(unused)]
pub fn checks(validate: &str, ciphertext_hash: &str) -> bool {
    let result = validate == ciphertext_hash;
    if result == true {
      return true
    } else {
      println!("{{\n  \"ERROR\": \"Ciphertext and/or password are not as expected. \
        The supplied password was wrong, the enchantress.toml was wrong, or the file was tampered with.\",");
      println!("  \"Found hash\": \"{}\",", validate);
      println!("  \"Expected hash\": \"{}\",", ciphertext_hash);
      return false
    };
}

/// Generate key material based on the password, nonce, and then
/// hash the hash by mixing two fixed values.
#[allow(unused)]
pub fn a2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    let mut rkm = [0u8; 32];
    let _ = Argon2::default().hash_password_into(password, salt, &mut okm);
    let _ = Argon2::default().hash_password_into(ENCHA, &okm,  &mut rkm);
    rkm
}

/// Use a SHA3 XOF to hash the ciphertext for integrity checking.
#[allow(unused)]
pub fn ciphertext_hash(password: &[u8], file_data: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(password);
    hasher.update(file_data);
    let mut reader = hasher.finalize_xof();
    let mut key = vec![0u8; length];
    XofReader::read(&mut reader, &mut key);
    key
}

/// Generate a timestamp + random nonce.
#[allow(unused)]
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp_nanos = now.as_nanos();
    nonce[0..8].copy_from_slice(&timestamp_nanos.to_le_bytes()[0..8]);
    let _ = OsRng.try_fill_bytes(&mut nonce[8..16]);
    nonce
}

/// Encrypt a file with AES-256 in CTR mode.
#[allow(unused)]
pub fn encrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
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
#[allow(unused)]
pub fn decrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
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
#[allow(unused)]
pub fn decrypt_stdout(input_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
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
