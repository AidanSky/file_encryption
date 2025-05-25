use std::io::prelude::*;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use hex;
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- File Encryption/Decryption Tool ---");

    let file_path = loop {
        let input = read_user_input("Please enter the path to the file: ");

        let trimmed_input = input.trim();

        let path_str = 
            if let Some(stripped) = trimmed_input.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                stripped
            } else if let Some(stripped) = trimmed_input.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
                stripped
            } else {
                trimmed_input
            };

        if path_str.is_empty() {
            println!("Error: Input cannot be empty. Please try again.");
            continue; // Ask again
        }

        let path = PathBuf::from(&path_str);

        if path.is_file() { 
            println!("File selected: {}", path.display());
            break path;
        } else if path.exists() { 
            println!("Error: '{}' exists but is not a file. Please enter a valid file path.", path.display());
        } else { 
            println!("Error: File '{}' does not exist. Please enter a valid file path.", path.display());
        }
    };

    let operation = loop {
        let input = read_user_input("Do you want to (e)ncrypt or (d)ecrypt? (e/d): ");
        match input.trim().to_ascii_lowercase().as_str() {
            "e" | "encrypt" => {
                println!("Operation: Encrypt");
                break "encrypt";
            }
            "d" | "decrypt" => {
                println!("Operation: Decrypt");
                break "decrypt";
            }
            _ => {
                println!("Invalid input. Please type 'e' for encrypt or 'd' for decrypt.");
            }
        }
    };

    let mut key_bytes: Vec<u8> = Vec::new();
    let mut nonce_bytes: Vec<u8> = Vec::new();

    // if decrypt, interpret key and nonce
    if operation == "decrypt" {
        let key_input = Some(read_user_input("Please enter the key for decryption (Hex/Base64): "));
        let nonce_input = Some(read_user_input("Please enter the nonce for decryption (Hex/Base64): "));

        // decode key & nonce
        if let Some(n) = &nonce_input {
            nonce_bytes = if n.len() == 24 && n.chars().all(|c| c.is_ascii_hexdigit()) {
                println!("Attempting to decode nonce as hex");
                hex::decode(n)?
            } else {
                println!("Attempting to decode nonce as base64");
                general_purpose::STANDARD.decode(n)?
            };
        };
        if let Some(k) = &key_input {
            key_bytes = if k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit()) {
                println!("Attempting to decode key as hex");
                hex::decode(k)?
            } else {
                println!("Attempting to decode key as base64");
                general_purpose::STANDARD.decode(k)?
            };
        }
    }
    
    // define variables to track directories
    let original_file: &PathBuf = &file_path;
    let original_name = file_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // needs to get rid of everything until after final /
    let base_name = original_name.rsplit_once('.').map_or(original_name, |(base, _ext)| base).to_string();
    let name_combined: String = format!("encryption_{}", base_name);
    let name_without_extension: &str = &name_combined;

    // check for existence of documents folder
    let mut directory = match dirs::document_dir() {
        Some(path) => path,
        None => {
            return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Could not find the documents directory.", )));
        }
    };

    // check for existence of encrypted_files folder in documents. If it doesn't exist, create it.
    directory.push("encrypted_files");
    match std::fs::create_dir_all(&directory) {
        Ok(_) => {
            println!("encrypted_files found/created successfully");
        }
        Err(e) => {
            return Err(Box::new(e));            
        }
    }

    // check if docs/encrypted_files/original_name already exists. If so, return an error
    directory.push(&name_without_extension);

    match std::fs::exists(&directory) {
        Ok(true) => {
            return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "documents/encrypted_files/originalname already exists. Please move/delete the original to avoid overwriting data", )));  
        }
        Ok(false) => {
            match std::fs::create_dir_all(&directory) {
                Ok(_) => {
                    println!("encrypted_files found/created successfully");
                }
                Err(e) => {
                    return Err(Box::new(e));            
                }
            }            
        }
        Err(e) => {
            return Err(Box::new(e));              
        }
    }

    // initialize function depending on if encrypt, decrypt, or fails
    match operation {
        "encrypt" => { 
            println!("initiating encryption function");
        // launch into encryption function (create encrypted file after returned or in function?)
            // println!("The original file is: {:?}", original_file);
            // println!("The new directory is: {:?}", directory);
            encrypt(&original_file, &directory)?;
        }
        "decrypt" => {
            println!("initiating decryption function");

            // launch into decryption function
            decrypt(&original_file, &key_bytes, &directory, &nonce_bytes)?;
        }
        _ => { 
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Third argument must be either 'encrypt' or decrypt'")));
        }
    }
    Ok(())
}

fn decrypt(original_directory: &Path, key_bytes: &Vec<u8>, copy_directory: &Path, nonce_bytes: &Vec<u8>) -> std::io::Result<()> {
    // Check if original exists. If not, throw an error. Should this error handling be done in the function, or before it is called? 

    // convert vector of key and nonce to true nonce and key
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or("");

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // read the file into a Vec<u8>
    let original_vec: Vec<u8> = std::fs::read(original_directory)?;

    // encrypt the Vec<u8>
    let decrypted_vec: Vec<u8> = cipher.decrypt(&nonce, original_vec.as_ref()).unwrap();

    // create directory for new file
        // define new string to push onto the copy_directory
    let final_path = format!("decrypted_{}", original_name);
    let mut decrypted_file_dir_buf = PathBuf::from(copy_directory);
    decrypted_file_dir_buf.push(final_path);

    // create a file comprised of the new vec<u8>, named with file type of the original file 
    let mut decrypted_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&decrypted_file_dir_buf)?;
    decrypted_file.write_all(decrypted_vec.as_slice())?;

    Ok(())
}

fn encrypt(original_directory: &Path, copy_directory: &Path) -> Result<(), Box<dyn std::error::Error>> { 
    // this should return 3 documents, one encrypted file, one nonce.txt, one key.txt

    // generate the nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let key = Aes256Gcm::generate_key(OsRng); // key is created randomly. Maybe let user pick their own? 

    // define hex and base64 versions of the nonce:
    let nonce_hex = hex::encode(nonce);
    let nonce_base64 = general_purpose::STANDARD.encode(nonce);

    // define hex and base64 versions of the key: 
    let key_hex = hex::encode(key);
    let key_base64 = general_purpose::STANDARD.encode(key);

    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or("");

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // read the file into a Vec<u8>
    let original_vec: Vec<u8> = std::fs::read(original_directory)?;

    // encrypt the Vec<u8>
    let encrypted_vec: Vec<u8> = cipher.encrypt(&nonce, original_vec.as_ref()).unwrap();

    // create directory for new file
        // define new string to push onto the copy_directory
    let final_path = format!("encrypted_{}", original_name);
    let mut encrypted_file_dir_buf = PathBuf::from(copy_directory);
    encrypted_file_dir_buf.push(final_path);

    // create a file comprised of the new vec<u8>, named with file type of the original file 
    let mut encrypted_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&encrypted_file_dir_buf)?;
    encrypted_file.write_all(encrypted_vec.as_slice())?;
    
    // create key.txt, nonce.txt, and actually encrypt the file, then creat encrytped_file
    let key_path = copy_directory.join("key.txt");
    let mut key_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&key_path)?;

    key_file.write_all("Key (Hex): ".as_bytes())?;
    key_file.write_all(key_hex.as_bytes())?;
    key_file.write_all(b"\n")?;
    key_file.write_all("Key (Base64): ".as_bytes())?;
    key_file.write_all(key_base64.as_bytes())?;

    let nonce_path = copy_directory.join("nonce.txt");
    let mut nonce_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&nonce_path)?;

    nonce_file.write_all("Nonce (Hex): ".as_bytes())?;
    nonce_file.write_all(nonce_hex.as_bytes())?;
    nonce_file.write_all(b"\n")?;
    nonce_file.write_all("Nonce (Base64): ".as_bytes())?;
    nonce_file.write_all(nonce_base64.as_bytes())?;

    Ok(())
}

fn read_user_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().expect("Failed to flush stdout");

    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input)
        .expect("Failed to read line");

    user_input.trim().to_string() // Trim whitespace and convert to owned String
}