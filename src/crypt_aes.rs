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

/// There are two arbitrary consants of sufficient length (46 bytes) used as fixed salts.
/// One of them is a "public const" named "MAGIC", while the other is
/// a private constant used within this module named "ENCHA".
#[allow(unused)]
pub const MAGIC: &[u8] = b"789c33a8303536333437323334b328353301001ccc0395";
#[allow(unused)]
const ENCHA: &[u8] = b"789c33a8303132733337373335732d353301001df903be";

/// This "checks" function is a string comparison function to ensure that the ciphertext hasn't been 
/// tampered with and that the key material is correct.
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

/// Generate key material with two rounds of Argon2id. 
/// The first round is based on the password and supplied salt.
/// The second round is the output of the first round and the "ENCHA" salt.
#[allow(unused)]
pub fn a2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    let mut rkm = [0u8; 32];
    let _ = Argon2::default().hash_password_into(password, salt, &mut okm);
    let _ = Argon2::default().hash_password_into(ENCHA, &okm,  &mut rkm);
    rkm
}

/// This function generates a SHA3 XOF with SHAKE 256.
/// The XOF (hash) has input of the password and the ciphertext so
/// that if either the password is incorrect or the ciphertext has been
/// modified, the value will change.
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

/// Generate a 16 byte nonces for AES-256 with eight bytes of a nanosecond timestamp and 8 bytes of appended random nonce.
#[allow(unused)]
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp_nanos = now.as_nanos();
    nonce[0..8].copy_from_slice(&timestamp_nanos.to_le_bytes()[0..8]);
    let _ = OsRng.try_fill_bytes(&mut nonce[8..16]);
    nonce
}

/// Encrypt a file with AES-256 in CTR mode. The function takes an input file, and output, and key to use for
/// the encryption. A nonce is generated using the generate_nonce function.
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
/// The output is any UTF-8 data. If the data is non-UTF-8,
/// decrypt to a file instead with the decrypt_file function.
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
