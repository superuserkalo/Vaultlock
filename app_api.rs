mod database;
mod prompt;
mod login;

mod hashing;
mod encryption;

use crate::app_api::prompt::prompt_for_username_and_master_key;
use crate::app_api::login::login_hash_comparison;

use crate::app_api::hashing::hash_credentials;
use crate::app_api::encryption::encrypt;
pub use crate::app_api::database::initialize_database;

pub fn app(){
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

pub fn run_app(db_path: &str) {
    let (master_username, master_key): (String, String) = prompt_for_username_and_master_key("Please enter Username: ", "Please enter Master-Key: ");
    if login_hash_comparison(db_path, &master_username, &master_key).expect("Login comparison failed!")
    {
        println!("Login successful!")
    } else {
        println!("Login failed!");
    }
}

pub fn initialize_app(db_path: &str) {
    let (master_username, master_key) = prompt_for_username_and_master_key("Please set Username: ", "Please set Master-Key: ");
    let (master_username_hash, master_key_hash) = hash_credentials(&master_username, &master_key);

    let (encrypted_username_hash, username_nonce) = encrypt(master_username_hash.as_bytes()).expect("Encryption failed");
    let (encrypted_master_key_hash, key_nonce) = encrypt(master_key_hash.as_bytes()).expect("Encryption failed");

    initialize_database(db_path, encrypted_username_hash, username_nonce, encrypted_master_key_hash, key_nonce).expect("DB initialization failed!");
    println!("Initialization successful!");
}