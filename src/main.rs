use std::fmt::Error;
use std::fs;
use std::io::prelude::*;
use std::io;
use std::env;
use std::path;
use std::path::Path;
use std::path::PathBuf;
use aes_gcm::aes::Aes128;
use rand::prelude::*;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use hex;
use base64::{engine::general_purpose, Engine as _};

// Should later be split into two functions, one for encrypting, one for decrypting
// how do I get rid of strings if they exist

// fn main() -> io::Result<()> {
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Collect arguments as vector. Should be arguments for input file, output file, encrypt vs decrypt, and maybe type of encryption?
    // instead of having argument for name of copy, just name it encrypted_'original_name'?
    // nonce and key currently only needed if decrypting 
    // let user decide key. If they don't, assume default and generate randomly?

    // include nonce and key as files instead of as text
    
    //ensure there is a way to change the directory that the original is located in.
    println!("--- File Encryption/Decryption Tool ---");

    // let file_directory = loop {
    //     let input = read_user_input("Please enter the file directory: ");
    //     let path = PathBuf::from(&input);
    //     if path.is_dir() {
    //         println!("Directory selected: {}", path.display());
    //         break path;
    //     } else if path.exists() {
    //         println!("Error: '{}' exists but is not a directory. Please enter a valid directory.", path.display());
    //     } else {
    //         println!("Error: Directory '{}' does not exist. Please enter a valid directory.", path.display());
    //     }
    // };

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

    let mut file_directory = Path::new("");
    if let Some(directory) = file_path.parent() {
        file_directory = directory;
    }

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

    let mut key_input: Option<String> = None;
    let mut nonce_input: Option<String> = None;
    let mut key_bytes: Vec<u8> = Vec::new();
    let mut nonce_bytes: Vec<u8> = Vec::new();

    // 3. If decrypt, then ask for key and nonce
    if operation == "decrypt" {
        key_input = Some(read_user_input("Please enter the key for decryption (Hex/Base64): "));
        nonce_input = Some(read_user_input("Please enter the nonce for decryption (Hex/Base64): "));

        // decode key & nonce
        if let Some(n) = &nonce_input {
            nonce_bytes = if n.len() == 24 && n.chars().all(|c| c.is_ascii_hexdigit()) {
                println!("Attempting to nonce decode as hex");
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
    
    // check if originalname exists
    // if exists, proceed. If not, exit 
    let original_file: &PathBuf = &file_path;
    let original_path = Path::new(&file_directory);
    let original_name = file_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // needs to get rid of everything until after final /
    let base_name = original_name.rsplit_once('.').map_or(original_name, |(base, _ext)| base).to_string();
    let name_combined: String = format!("encryption_{}", base_name);
    let name_without_extension: &str = &name_combined;

    println!("the original file as of line 130: {:?}", original_file);

    // match fs::exists(original_path) {
    //     Ok(true) => {
    //         println!("Original item found!");
    //     } 
    //     Ok(false) => {
    //         println!("Original item not found. Please double check the path!");
    //         return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Original item not found"));
    //     }
    //     Err(e) => {
    //         println!("Unrecoverable error occurred when checking if file exists.");
    //         return Err(e);
    //     }
    // }

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
            return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Could not create/find encrypted_files directory.", )));            
        }
    }

    // check if docs/encrypted_files/original_name already exists. If so, return an error
    directory.push(&name_without_extension); // this needs a way to cutoff everything until final file name

    println!("test {:?}", original_path);
    println!("The directory is: {:?}", directory);

    match std::fs::exists(&directory) {
        Ok(true) => {
            return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "encrypted_files{originalname} already exists. Please move/delete the original to avoid overwriting data", )));  
        }
        Ok(false) => {
            match std::fs::create_dir_all(&directory) {
                Ok(_) => {
                    println!("encrypted_files found/created successfully");
                }
                Err(e) => {
                    return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Could not create/find encrypted_files/{originalname} directory.", )));            
                }
            }            
        }
        Err(e) => {
            return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Could not create encrypted_files/{originalname} directory.", )));              
        }
    }

    // initialize function depending on if encrypt, decrypt, or fails
    match operation {
        "encrypt" => { 
            println!("initiating encryption function");
        // launch into encryption function (create encrypted file after returned or in function?)
            println!("The original file is: {:?}", original_file);
            println!("The new directory is: {:?}", directory);
            encrypt(&original_file, &directory)?;
        }
        "decrypt" => {
            println!("initiating decryption function");
            println!("Key bytes is: {:?}", key_bytes);

            // unwrap key_bytes and nonce_bytes

            // launch into decryption function
            decrypt(&original_file, &key_bytes, &directory, &nonce_bytes)?;
        }
        _ => { 
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Third argument must be either 'encrypt' or decrypt'")));
        }
    }
    // copy the file to another file
    // use OpenOption, so if copy doesn't exist, it can be created. Should it be overwritten?
    Ok(())
}

fn decrypt(original_directory: &Path, key_bytes: &Vec<u8>, copy_directory: &Path, nonce_bytes: &Vec<u8>) -> std::io::Result<()> { // should copy be taken as an argument here, or only returned? Should these be std::fs::file or std::fs::OpenOptions?
    // Check if original exists. If not, throw an error. Should this error handling be done in the function, or before it is called? 
    // should file be created here, or should it just be returned?

    // convert vector of key and nonce to true nonce and key
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // needs to get rid of everything until after final /

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // extract only file type
    let file_type = original_directory.extension().unwrap().to_str().unwrap(); // this line of code needs to be changed

    // read the file into a Vec<u8>
    let original_vec: Vec<u8> = std::fs::read(original_directory)?;

    // encrypt the Vec<u8>
    let decrypted_vec: Vec<u8> = cipher.decrypt(&nonce, original_vec.as_ref()).unwrap(); // fix the lazy error handling with unwrap

    // create directory for new file
        // define new string to push onto the copy_directory
    let additional_string = format!("decrypted_{}.{}", original_name, file_type);
    let mut decrypted_file_dir_buf = PathBuf::from(copy_directory);
    decrypted_file_dir_buf.push(additional_string);
    // let encrypted_file_dir = encrypted_file_dir_buf.as_path();

    // create a file comprised of the new vec<u8>, named with file type of the original file 
    let mut decrypted_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&decrypted_file_dir_buf)?;
    decrypted_file.write_all(decrypted_vec.as_slice())?;

    Ok(())
}

fn encrypt(original_directory: &Path, copy_directory: &Path) -> Result<(), Box<dyn std::error::Error>> {    // this line of code needs to be changed
    // this should return 3 documents, one encrypted file, one nonce.txt, one key.txt

    // generate the nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let key = Aes256Gcm::generate_key(OsRng); // key can be generated randomly, or this can be adjusted to a user selected pass

    // define hex and base64 versions of the nonce:
    let nonce_hex = hex::encode(nonce);
    let nonce_base64 = general_purpose::STANDARD.encode(nonce);

    // define hex and base64 versions of the key: 
    let key_hex = hex::encode(key);
    let key_base64 = general_purpose::STANDARD.encode(key);

    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // needs to get rid of everything until after final /

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // extract only file type
    let file_type = original_directory.extension().unwrap().to_str().unwrap(); // this line of code needs to be changed

    // read the file into a Vec<u8>
    let original_vec: Vec<u8> = std::fs::read(original_directory)?;

    // encrypt the Vec<u8>
    let encrypted_vec: Vec<u8> = cipher.encrypt(&nonce, original_vec.as_ref()).unwrap(); // fix lazy

    // create directory for new file
        // define new string to push onto the copy_directory
    let additional_string = format!("encrypted_{}.{}", original_name, file_type);
    let mut encrypted_file_dir_buf = PathBuf::from(copy_directory);
    encrypted_file_dir_buf.push(additional_string);
    // let encrypted_file_dir = encrypted_file_dir_buf.as_path();

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