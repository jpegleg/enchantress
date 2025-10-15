use aes_gcm::{
    aead::{AeadCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};

use std::fs::File;
use std::io::{Read, Write};

/// Encrypt a file with AES-256 in GCM mode.
#[allow(deprecated)]
#[allow(unused)]
pub fn aead_encrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(&input_file)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let xkey = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(xkey);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher.encrypt(&nonce, &*data);

    let mut output = File::create(output_file)?;
    output.write_all(&nonce)?;
    output.write_all(&data)?;
    Ok(())
}

/// Decrypt a file with AES-256 in GCM mode.
#[allow(deprecated)]
#[allow(unused)]
pub fn aead_decrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut inonce = [0u8; 12];
    file.read_exact(&mut inonce)?;
    let nonce = Nonce::from_slice(&inonce);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let xkey = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(xkey);
    cipher.decrypt(&nonce, &*data);

    let mut output = File::create(output_file)?;
    output.write_all(&data)?;

    Ok(())
}


/// Decrypt a file to STDOUT with AES-256 in GCM mode.
/// The output is any UTF-8 data. If the data is non-UTF-8,
/// decrypt to a file instead with the aead_decrypt_file function.
#[allow(deprecated)]
#[allow(unused)]
pub fn aead_decrypt_stdout(input_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut inonce = [0u8; 12];
    file.read_exact(&mut inonce)?;
    let nonce = Nonce::from_slice(&inonce);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let xkey = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(xkey);
    cipher.decrypt(&nonce, &*data);

    println!("{}", String::from_utf8_lossy(&data).to_string());

    Ok(())
}
