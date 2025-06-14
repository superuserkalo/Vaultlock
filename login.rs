use std::convert::TryInto;
use std::error::Error;
use argon2::{Argon2, password_hash::{PasswordHash, PasswordVerifier}};
use rusqlite::Connection;
use crate::app_api::encryption::decrypt;

pub fn login_hash_comparison(db_path: &str, master_username: &str, master_key: &str) -> Result<bool, Box<dyn Error>> {
    let conn: Connection = Connection::open(db_path)?;

    let (db_encrypted_master_username_hash, db_username_nonce): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT encrypted_username_hash, username_nonce FROM master",
        [],
        |row| Ok((row.get(0)?, row.get(1)?))
    )?;

    let (db_encrypted_master_key_hash, db_key_nonce): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT encrypted_master_key_hash, key_nonce FROM master",
        [],
        |row| Ok((row.get(0)?, row.get(1)?))
    )?;

    let db_decrypted_master_username_hash = decrypt(
        &db_encrypted_master_username_hash,
        db_username_nonce.as_slice().try_into().map_err(|_| "Invalid nonce size")?
    ).map_err(|e| format!("Username decryption error: {:?}", e))?;

    let db_decrypted_master_key_hash = decrypt(
        &db_encrypted_master_key_hash,
        db_key_nonce.as_slice().try_into().map_err(|_| "Invalid nonce size")?
    ).map_err(|e| format!("Master key decryption error: {:?}", e))?;

    let db_master_username_hash = std::str::from_utf8(&db_decrypted_master_username_hash)?;
    let db_master_key_hash = std::str::from_utf8(&db_decrypted_master_key_hash)?;

    let db_master_username_hash = PasswordHash::new(db_master_username_hash)
        .map_err(|e| format!("Invalid username hash: {}", e))?;
    let db_master_key_hash = PasswordHash::new(db_master_key_hash)
        .map_err(|e| format!("Invalid master key hash: {}", e))?;

    let argon2 = Argon2::default();

    let master_username_verification = argon2.verify_password(master_username.as_bytes(), &db_master_username_hash).is_ok();

    let master_key_verification = argon2.verify_password(master_key.as_bytes(), &db_master_key_hash).is_ok();

    Ok(master_username_verification && master_key_verification)
}