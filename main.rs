use std::error::Error;
use std::io::{self, Write};
use std::convert::TryInto;
use aes_gcm::{
    aead::{Aead, generic_array::GenericArray, KeyInit},
    Aes256Gcm,
    Key,
};
use argon2::{
    Argon2,
    password_hash::{
        PasswordHash,
        PasswordHasher,
        PasswordVerifier,
        rand_core::OsRng,
        SaltString,
    },
};
use rusqlite::{Connection, params};
use rand::RngCore;
use rpassword::read_password;

const KEY_SIZE: usize = 32; // AES-256 key size in bytes
const NONCE_SIZE: usize = 12; // Nonce size for AES-GCM

// Database functions
fn initialize_database(
    db_path: &str,
    encrypted_master_username_hash: Vec<u8>,
    username_nonce: [u8; NONCE_SIZE],
    encrypted_master_key_hash: Vec<u8>,
    key_nonce: [u8; NONCE_SIZE],
) -> Result<(), Box<dyn Error>> {
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_username_hash BLOB NOT NULL,
            username_nonce BLOB NOT NULL,
            encrypted_master_key_hash BLOB NOT NULL,
            key_nonce BLOB NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "INSERT INTO master (encrypted_username_hash, username_nonce, encrypted_master_key_hash, key_nonce)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            encrypted_master_username_hash,
            username_nonce,
            encrypted_master_key_hash,
            key_nonce
        ],
    )?;

    Ok(())
}

// Encryption functions
fn generate_aes_key() -> [u8; KEY_SIZE] {
    [0u8; KEY_SIZE]
}

fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), aes_gcm::Error> {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = generate_nonce();
    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext)?;
    Ok((ciphertext, nonce))
}

fn decrypt(ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)?;
    Ok(plaintext)
}

// Hashing functions
fn hash_credentials(master_username: &str, master_key: &str) -> (String, String) {
    let username_salt = SaltString::generate(&mut OsRng);
    let master_key_salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let master_username_hash = argon2
        .hash_password(master_username.as_bytes(), &username_salt)
        .expect("Failed to hash master_username")
        .to_string();

    let master_key_hash = argon2
        .hash_password(master_key.as_bytes(), &master_key_salt)
        .expect("Failed to hash master_key")
        .to_string();

    (master_username_hash, master_key_hash)
}

// Login functions
fn login_hash_comparison(
    db_path: &str,
    master_username: &str,
    master_key: &str,
) -> Result<bool, Box<dyn Error>> {
    let conn = Connection::open(db_path)?;

    let (db_encrypted_master_username_hash, db_username_nonce): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT encrypted_username_hash, username_nonce FROM master",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let (db_encrypted_master_key_hash, db_key_nonce): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT encrypted_master_key_hash, key_nonce FROM master",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let db_decrypted_master_username_hash = decrypt(
        &db_encrypted_master_username_hash,
        db_username_nonce
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid nonce size")?,
    )
    .map_err(|e| format!("Username decryption error: {:?}", e))?;

    let db_decrypted_master_key_hash = decrypt(
        &db_encrypted_master_key_hash,
        db_key_nonce
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid nonce size")?,
    )
    .map_err(|e| format!("Master key decryption error: {:?}", e))?;

    let db_master_username_hash = std::str::from_utf8(&db_decrypted_master_username_hash)?;
    let db_master_key_hash = std::str::from_utf8(&db_decrypted_master_key_hash)?;

    let db_master_username_hash =
        PasswordHash::new(db_master_username_hash).map_err(|e| format!("Invalid username hash: {}", e))?;
    let db_master_key_hash =
        PasswordHash::new(db_master_key_hash).map_err(|e| format!("Invalid master key hash: {}", e))?;

    let argon2 = Argon2::default();

    let master_username_verification =
        argon2.verify_password(master_username.as_bytes(), &db_master_username_hash).is_ok();
    let master_key_verification =
        argon2.verify_password(master_key.as_bytes(), &db_master_key_hash).is_ok();

    Ok(master_username_verification && master_key_verification)
}

// Prompt functions
fn prompt_for_username_and_master_key(
    prompt_username: &str,
    prompt_master_key: &str,
) -> (String, String) {
    print!("{}", prompt_username);
    io::stdout().flush().expect("Failed to flush stdout");

    let mut master_username = String::new();
    io::stdin()
        .read_line(&mut master_username)
        .expect("Invalid Input");
    let master_username = master_username.trim().to_string();

    print!("{}", prompt_master_key);
    io::stdout().flush().expect("Failed to flush stdout");

    let master_key = read_password()
        .expect("Failed to read password")
        .trim()
        .to_string();

    (master_username, master_key)
}

// Main application functions
fn run_app(db_path: &str) {
    let (master_username, master_key): (String, String) =
        prompt_for_username_and_master_key("Please enter Username: ", "Please enter Master-Key: ");

    if login_hash_comparison(db_path, &master_username, &master_key).expect("Login comparison failed!") {
        println!("Login successful!")
    } else {
        println!("Login failed!");
    }
}

fn initialize_app(db_path: &str) {
    let (master_username, master_key) =
        prompt_for_username_and_master_key("Please set Username: ", "Please set Master-Key: ");

    let (master_username_hash, master_key_hash) = hash_credentials(&master_username, &master_key);

    let (encrypted_username_hash, username_nonce) =
        encrypt(master_username_hash.as_bytes()).expect("Encryption failed");

    let (encrypted_master_key_hash, key_nonce) =
        encrypt(master_key_hash.as_bytes()).expect("Encryption failed");

    initialize_database(
        db_path,
        encrypted_username_hash,
        username_nonce,
        encrypted_master_key_hash,
        key_nonce
    ).expect("DB initialization failed!");

    println!("Initialization successful!");
}

fn app() {
    // Path to the database file
    let db_path: &str = "vault.db";
    // Check if the database file exists
    let db_check: bool = std::path::Path::new(db_path).is_file();

    if db_check {
        run_app(db_path);
    } else {
        initialize_app(db_path);
    }
}

fn main() {
    app();
}






