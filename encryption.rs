use aes_gcm::{aead::{Aead, generic_array::GenericArray, KeyInit}, Aes256Gcm, Key};
use argon2::password_hash::rand_core::OsRng;
use rand::RngCore;

pub const KEY_SIZE: usize = 32; // AES-256 key size in bytes
pub const NONCE_SIZE: usize = 12; // Nonce size for AES-GCM

pub fn generate_aes_key() -> [u8; KEY_SIZE] {
[0u8; KEY_SIZE]
}

pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    nonce
}

// Encrypt plaintext using AES-GCM with a given key and nonce and return ciphertext
pub fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), aes_gcm::Error> {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = generate_nonce();
    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext)?;
    Ok((ciphertext, nonce))
}
// Decrypt ciphertext using AES-GCM with a given key and nonce and return plaintext
pub fn decrypt(ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)?;
    Ok(plaintext)
}