use std::error::Error;
use rusqlite::{Connection, params};
const NONCE_SIZE: usize = 12; // Nonce size for AES-GCM

pub fn initialize_database(db_path: &str, encrypted_master_username_hash: Vec<u8>, username_nonce: [u8; NONCE_SIZE], encrypted_master_key_hash: Vec<u8>, key_nonce: [u8; NONCE_SIZE]) -> Result<(), Box<dyn Error>> {
    let conn: Connection = Connection::open(db_path)?;

    conn.execute(
        "
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_username_hash BLOB NOT NULL,
            username_nonce BLOB NOT NULL,
            encrypted_master_key_hash BLOB NOT NULL,
            key_nonce BLOB NOT NULL
        )
        ",
        [],
    )?;

    conn.execute(
        "
        INSERT INTO master (encrypted_username_hash, username_nonce, encrypted_master_key_hash, key_nonce) VALUES (?1, ?2, ?3, ?4)
        ",
        params![encrypted_master_username_hash, username_nonce, encrypted_master_key_hash, key_nonce],
    )?;

    Ok(())
}