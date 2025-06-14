use argon2::{Argon2, password_hash::{PasswordHasher, rand_core::OsRng, SaltString}};

pub fn hash_credentials(master_username: &str, master_key: &str) -> (String, String) {
    // Generate a unique salt for the username
    let username_salt: SaltString = SaltString::generate(&mut OsRng);
    // Generate a unique salt for the master key
    let master_key_salt: SaltString = SaltString::generate(&mut OsRng);

    let argon2: Argon2 = Argon2::default();

    // Hash the username with the generated salt
    let master_username_hash = argon2.hash_password(master_username.as_bytes(), &username_salt).expect("Failed to hash master_username").to_string();
    // Hash the master key with the generated salt
    let master_key_hash = argon2.hash_password(master_key.as_bytes(), &master_key_salt).expect("Failed to hash master_key").to_string();

    (master_username_hash, master_key_hash)
}