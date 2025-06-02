use std::io::prelude::*;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use aes_gcm::aes::Aes256;
// use aes_gcm::AesGcm;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Nonce, Key
};
use argon2::Argon2;

const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12; //how long r nonces lol TODO
const KEY_LENGTH: usize = 32; // 32 bytes long, 256 bits

// implement enumerator for ensuring proper error handling for different option types
#[derive(Debug)]
pub enum EncryptionError {
    Io(std::io::Error),
    Aead(aes_gcm::Error),
    InvalidKeyLength(String),
    InvalidNonceLength(String),
    PathHandling(String),
    FileNameExtraction,
    FileStemExtraction,
    FileExtensionExtraction,
    Utf8Conversion,
    InputFileNotAFile,
    InputFileNotFound,
    OutputDirectoryError(String),
    Argon2(argon2::Error),
}

// implement display trait
impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::Io(e) => write!(f, "IO error: {}", e),
            EncryptionError::Aead(e) => write!(f, "AEAD (Decryption) error: {}", e),
            EncryptionError::InvalidKeyLength(s) => write!(f, "Invalid key length: {}", s),
            EncryptionError::InvalidNonceLength(s) => write!(f, "Invalid nonce length: {}", s),
            EncryptionError::PathHandling(s) => write!(f, "Path handling error: {}", s),
            EncryptionError::FileNameExtraction => write!(f, "Could not extract filename."),
            EncryptionError::FileStemExtraction => write!(f, "Could not extract file stem."),
            EncryptionError::FileExtensionExtraction => write!(f, "Could not extract file extension."),
            EncryptionError::Utf8Conversion => write!(f, "Filename, stem, or extension is not valid UTF-8."),
            EncryptionError::InputFileNotAFile => write!(f, "Input path is not a file."),
            EncryptionError::InputFileNotFound => write!(f, "Input file not found."),
            EncryptionError::OutputDirectoryError(s) => write!(f, "Output directory error: {}", s),
            EncryptionError::Argon2(e) => write!(f, "Key derivation error: {}", e),
        }
    }
}

impl std::error::Error for EncryptionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EncryptionError::Io(e) => Some(e),
            EncryptionError::Aead(e) => Some(e),
            // EncryptionError::Argon2(e) => Some(e), // why not work? TODO
            _ => None,
        }
    }
}

impl From<std::io::Error> for EncryptionError {
    fn from(err: std::io::Error) -> EncryptionError {
        EncryptionError::Io(err)
    }
}

impl From<aes_gcm::Error> for EncryptionError {
    fn from(err: aes_gcm::Error) -> EncryptionError {
        EncryptionError::Aead(err)
    }
}

impl From<argon2::Error> for EncryptionError {
    fn from(err: argon2::Error) -> EncryptionError {
        EncryptionError::Argon2(err)
    }
}

fn main() -> Result<(), EncryptionError> {
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

    // if decrypt, interpret key and nonce
    let password = Some(read_user_input("Please enter the password: "));

    let delete_original: bool = loop {
        let input = read_user_input("Would you like the original file to be deleted? (y)es or (n)o: ");

        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => {
                println!("The original file will be deleted.");
                break true;
            }
            "n" | "no" => {
                println!("The original file will be kept.");
                break false;
            }
            _ => {
                println!("Please enter either 'y' or 'n'.");
            }
        }
    };
    
    // define variables to track directories
    let mut key_bytes = [0u8; KEY_LENGTH]; // should this be a vec instead?
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    let mut salt_bytes = [0u8; SALT_LENGTH];
    let mut password_bytes: Vec<u8> = Vec::new();

    if let Some(n) = &password {
        password_bytes = n.as_bytes().to_vec();
    }

    let original_file_path: &PathBuf = &file_path;
    let file_pathbuf = file_path.clone();
    let original_name = file_pathbuf.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // is thisn ecessary? needs to get rid of everything until after final /
    let base_name = original_name.rsplit_once('.').map_or(original_name, |(base, _ext)| base).to_string();
    let mut _name_combined = String::new();
    if operation == "encrypt" {
        _name_combined = format!("encrypted_{}", base_name);
    } else {
        _name_combined = format!("decrypted_{}", base_name);        
    }

    let name_without_extension: &str = &_name_combined;

    // check for existence of documents folder
    let mut directory = match dirs::document_dir() {
        Some(path) => path,
        None => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Could not find the documents directory.", ).into());
        }
    };

    // check for existence of encrypted_files folder in documents. If it doesn't exist, create it.
    directory.push("encrypted_files");
    match std::fs::create_dir_all(&directory) {
        Ok(_) => {
            println!("encrypted_files folder found/created successfully");
        }
        Err(e) => {
            return Err(e.into());            
        }
    }

    // check if docs/encrypted_files/original_name already exists. If so, return an error
    directory.push(&name_without_extension);

    match std::fs::exists(&directory) {
        Ok(true) => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "documents/encrypted_files/originalname already exists. Please move/delete the original to avoid overwriting data", ).into());  
        }
        Ok(false) => {
            match std::fs::create_dir_all(&directory) {
                Ok(_) => {
                    println!("{:?} folder created successfully", name_without_extension);
                }
                Err(e) => {
                    return Err(e.into());            
                }
            }            
        }
        Err(e) => {
            return Err(e.into());              
        }
    }

    // initialize function depending on if encrypt, decrypt, or fails
    match operation {
        "encrypt" => { 
            println!("initiating encryption function");
            // launch into encryption function (create encrypted file after returned or in function?)
            // println!("The original file is: {:?}", original_file);
            // println!("The new directory is: {:?}", directory);

            // create salt //should this be done in the function instead?
            OsRng.fill_bytes(&mut salt_bytes);

            // initialize key based on salt and password
            Argon2::default().hash_password_into(&password_bytes, &salt_bytes, &mut key_bytes)?;

            encrypt(&original_file_path, &directory, delete_original, &key_bytes, salt_bytes)?;
        }
        "decrypt" => {
            println!("initiating decryption function");

            // if operation is decrypt, locate first 16 and parse them into nonce_base64, then convert that into nonce-bytes
            // read out all bytes of the nonce at the beginning of the file
                // better to do this here or once file has already been assigned a variable and stuff? 
            let temp_file: std::fs::File = std::fs::File::open(file_path.clone())?;
            let mut byte_theft = [0u8; SALT_LENGTH+NONCE_LENGTH];
            let pre_entry: u64 = byte_theft.len() as u64;
            // let mut nonce_buffer = [0u8; NONCE_LENGTH]; // is 16 correct here? should this be 0u8 or u8?
            // let nonce_base64_result = temp_file.take(12).read_exact(&mut nonce_bytes)?;
            let mut header_reader = (&temp_file).take(pre_entry);
            header_reader.read_exact(&mut byte_theft)?;
            // nonce_bytes = nonce_buffer;

            nonce_bytes.copy_from_slice(&byte_theft[0..NONCE_LENGTH]);
            salt_bytes.copy_from_slice(&byte_theft[NONCE_LENGTH..(NONCE_LENGTH + SALT_LENGTH)]);

            // if operation is decrypt, locate the salt, which should come directly after the nonce 
            // let mut salt_buffer = [0u8; SALT_LENGTH];
            // let salt_base64_result = temp_file.take(16).read_exact(&mut salt_bytes)?;
            // temp_file.take(16).read_exact(&mut salt_bytes)?;
            // salt_bytes = salt_buffer; //TODO this is an unncessary conversion

            // take password and salt then derive vec<u8> key
            Argon2::default().hash_password_into(&password_bytes, &salt_bytes, &mut key_bytes)?;

            // launch into decryption function
            // TODO should passwords outside of size ;32 be allowed? 
            decrypt(&original_file_path, &temp_file, &key_bytes, &directory, nonce_bytes, delete_original)?;
        }
        _ => { 
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Third argument must be either 'encrypt' or decrypt'").into());
        }
    }
    Ok(())
}

fn decrypt(original_directory: &Path, mut original_file: &std::fs::File, key_bytes: &[u8; KEY_LENGTH], copy_directory: &Path, nonce_bytes: [u8; NONCE_LENGTH], delete_original: bool) -> Result<(), EncryptionError> {    
    // convert vector of key and nonce to true nonce and key
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or("");

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // read the file into a Vec<u8>
    // let original_vec: Vec<u8> = std::fs::read(original_directory)?;
    // Does this already have the first 16+12 bytes ignored?
    let mut original_vec: Vec<u8> = Vec::new();
    original_file.read_to_end(&mut original_vec)?;

    // decrypt the Vec<u8>
    let decrypted_vec: Vec<u8> = cipher.decrypt(&nonce, original_vec.as_ref())?;

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

    if delete_original {
        std::fs::remove_file(original_directory)?;
        println!("Successfully removed {:?}", original_directory);
    }

    println!("Decryption function succeeded sucessfully");

    Ok(())
}

fn encrypt(original_directory: &Path, copy_directory: &Path, delete_original: bool, key_bytes: &[u8; KEY_LENGTH], salt_bytes: [u8; SALT_LENGTH]) -> Result<(), EncryptionError> { 
    // this should return 3 documents, one encrypted file, one nonce.txt, one key.txt

    // generate the nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // let key = Aes256Gcm::generate_key(OsRng); // key is created randomly. Maybe let user pick their own? 
    let key = Key::<Aes256>::from_slice(key_bytes);

    // define salt in scope
    let salt = salt_bytes;

    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or("");

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // read the file into a Vec<u8>
    // let original_vec: Vec<u8> = std::fs::read(original_directory)?;
    let mut original_vec: Vec<u8> = Vec::new();
    original_vec.extend_from_slice(&nonce);
    original_vec.extend_from_slice(&salt);

    // define the vec for the original file, to be encrypted then appended
    let original_file_vec: Vec<u8> = std::fs::read(original_directory)?;
    // original_vec.append(&mut original_file_vec);

    let mut encrypted_file_vec: Vec<u8> = cipher.encrypt(&nonce, original_file_vec.as_ref())?;

    // encrypt the Vec<u8>
    original_vec.append(&mut encrypted_file_vec);

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
    encrypted_file.write_all(original_vec.as_slice())?;

    if delete_original {
        std::fs::remove_file(original_directory)?;
        println!("Successfully removed {:?}", original_directory);
    }

    println!("Encryption completed successfully! Check documents/encrypted_items");

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