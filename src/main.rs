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

// Should later be split into two functions, one for encrypting, one for decrypting

fn main() -> io::Result<()> {

    // Collect arguments as vector. Should be arguments for input file, output file, encrypt vs decrypt, and maybe type of encryption?
    // instead of having argument for name of copy, just name it encrypted_'original_name'?
    // nonce and key currently only needed if decrypting 
    // let user decide key. If they don't, assume default and generate randomly?

    // include nonce and key as files instead of as text
    
    //ensure there is a way to change the directory that the original is located in.

    let args: Vec<String> = env::args().collect();

    // Include extra arg for different encryption methods later?
    if args[1] == "encrypt" && args.len() != 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Ensure arguments are valid (file_name, encrypt || decrypt, key (if decrypting), nonce (if decrypting)"));
    }

    // if decrypting, a nonce must be included
    if args[1] == "decrypt" && args.len() != 4{
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "If decrypting, nonce and key must be included"));
    }
    
    // where to include randomness for encryption?

    // check if originalname exists & is .txt (is this already done in the code above)
    // if exists, proceed. If not, exit 
    let original_path = Path::new(&args[0]);
    let original_name = original_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // needs to get rid of everything until after final /

    match fs::exists(original_path) {
        Ok(true) => {
            println!("Original item found!");
        } 
        Ok(false) => {
            println!("Original item not found. Please double check the path!");
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Original item not found"));
        }
        Err(e) => {
            println!("Unrecoverable error occurred when checking if file exists.");
            return Err(e);
        }
    }

    // check for existence of documents folder
    let mut directory = match dirs::document_dir() {
        Some(path) => path,
        None => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Could not find the documents directory.", ));
        }
    };

    // check for existence of encrypted_files folder in documents. If it doesn't exist, create it.
    directory.push("encrypted_files");
    match std::fs::create_dir_all(&directory) {
        Ok(_) => {
            println!("encrypted_files found/created successfully");
        }
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Could not create/find encrypted_files directory.", ));            
        }
    }

    // check if docs/encrypted_files/original_name already exists. If so, return an error
    directory.push(original_path); // this needs a way to cutoff everything until final file name

    match std::fs::exists(&directory) {
        Ok(true) => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "encrypted_files{originalname} already exists. Please move/delete the original to avoid overwriting data", ));  
        }
        Ok(false) => {
            match std::fs::create_dir_all(&directory) {
                Ok(_) => {
                    println!("encrypted_files found/created successfully");
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "Could not create/find encrypted_files/{originalname} directory.", ));            
                }
            }            
        }
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Could not create encrypted_files/{originalname} directory.", ));              
        }
    }

    // initialize function depending on if encrypt, decrypt, or fails
    match args.get(2) {
        Some(s) => {
            match s.to_lowercase().as_str() {
                "encrypt" => { 
                    println!("initiating encryption function");

                    // initialize files here or in the function?    
                        // create file that new data will be imprinted in here or in function? Directory must match  
                    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                    let key = Aes256Gcm::generate_key(OsRng); // key can be generated randomly, or this can be adjusted to a user selected pass

                    // launch into encryption function (create encrypted file after returned or in function?)
                    match std::fs::File::open(original_path) {
                        Ok(mut original_path) => {
                            encrypt(&original_path, &key, &directory, &nonce);
                        }
                        Err(e) => {
                            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Something went wrong when accessing original file."));
                        }
                    }
                }
                "decrypt" => {
                    println!("initiating decryption function");

                    // initialize functions here or in the function?
                    let nonce = Nonce::from_slice(&args[3].to_bytes());

                    // launch into decryption function
                    decrypt(&original_path, &key, &directory, &nonce);
                }
                _ => { 
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Third argument must be either 'encrypt' or decrypt'"));
                }
            }
        }
        None => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing command line argument. Expected either 'encrypt' or 'decrypt'"));
        }
    }

    // INCLUDE EPRINTLN! LINES FOR ALL POSSIBLE ERRORS 
    //    if let Err(e) = handle_command(arg1) {
    //     eprintln!("Error: {}", e);
    // }



    // copy the file to another file
    // use OpenOption, so if copy doesn't exist, it can be created. Should it be overwritten?
    Ok(())
}

fn decrypt(original_directory: &Path, key: &Key::<Aes256Gcm>, copy_directory: &Path, nonce: Nonce<>) -> std::io::Result<()> { // should copy be taken as an argument here, or only returned? Should these be std::fs::file or std::fs::OpenOptions?
    // Check if original exists. If not, throw an error. Should this error handling be done in the function, or before it is called? 
    // should file be created here, or should it just be returned?
    
    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // needs to get rid of everything until after final /

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // extract only file type
    let file_type = original_directory.extension().unwrap().to_str().unwrap(); // this line of code needs to be changed

    // read the file into a Vec<u8>
    let original_vec: Vec<u8> = std::fs::read(original_directory)?;

    // encrypt the Vec<u8>
    let decrypted_vec: Vec<u8> = cipher.decrypt(&nonce, original_vec.as_ref())?;

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

fn encrypt(original_directory: &Path, key: &Key::<Aes256Gcm>, copy_directory: &Path, nonce: Nonce<>) -> std::io::Result<()> {    // this line of code needs to be changed
    // this should return 3 documents, one encrypted file, one nonce.txt, one key.txt

    // define file name from path
    let original_name = original_directory.file_name().unwrap_or_else(|| std::ffi::OsStr::new("")).to_str().unwrap_or(""); // needs to get rid of everything until after final /

    // define the cipher
    let cipher = Aes256Gcm::new(&key);

    // extract only file type
    let file_type = original_directory.extension().unwrap().to_str().unwrap(); // this line of code needs to be changed

    // read the file into a Vec<u8>
    let original_vec: Vec<u8> = std::fs::read(original_directory)?;

    // encrypt the Vec<u8>
    let encrypted_vec: Vec<u8> = cipher.encrypt(&nonce, original_vec.as_ref()).unwrap();

    // create directory for new file
        // define new string to push onto the copy_directory
    let additional_string = format!("encrypted_{}.{}", original_name, file_type);
    let mut encrypted_file_dir_buf = PathBuf::from(copy_directory);
    encrypted_file_dir_buf.push(additional_string);
    // let encrypted_file_dir = encrypted_file_dir_buf.as_path();

    // create a file comprised of the new vec<u8>, named with file type of the original file 
    let encrypted_file = std::fs::OpenOptions::new()
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

    key_file.write_all(key)?;

    let nonce_path = copy_directory.join("nonce.txt");
    let mut nonce_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&nonce_path)?;

    nonce_file.write_all(nonce.as_bytes())?;

    Ok(())
}