use std::io::{self, Write};
use rpassword::read_password;

pub fn prompt_for_username_and_master_key(prompt_username: &str, prompt_master_key: &str) -> (String, String) {
    // Prompt for the username
    print!("{}", prompt_username);
    io::stdout().flush().expect("Failed to flush stdout");

    // Read the username input from the user
    let mut master_username = String::new();
    io::stdin().read_line(&mut master_username).expect("Invalid Input");
    let master_username = master_username.trim().to_string();

    // Prompt for the master key
    print!("{}", prompt_master_key);
    io::stdout().flush().expect("Failed to flush stdout");

    // Read the password input from the user
    let master_key = read_password().expect("Failed to read password").trim().to_string();

    (master_username, master_key)
}