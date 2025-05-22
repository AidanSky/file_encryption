use std::fmt::Error;
use std::fs;
use std::io::prelude::*;
use std::io;
use std::env;

// Should later be split into two functions, one for encrypting, one for decrypting

fn main() -> io::Result<()> {

    // Collect arguments as vector. Should be arguments for input file, output file, encrypt vs decrypt, and maybe type of encryption?
    // instead of having argument for name of copy, just name it encrypted_'original_name'?
    let args: Vec<String> = env::args().collect();

    // if args is smaller than 3 or greater than 4, return error
    if args.len() > 4 || args.len() < 3 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Ensure arguments are valid (input_name.txt, output_name.txt, encrypt || decrypt, encryption_method"));
    }

    // if args 1, 2, 3 are missing, return error. If arg 4 is missing, assume default AES256
    
    // is extra argument needed for password/randomness?
    // where to include randomness for encryption?

    // define original name based on match if exists in args and ensure it follows format (.txt only for now)

    // include function to determine type of encryption in args[3]

    if !&args[0].ends_with(".txt") {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "First argument not valid (must end with .txt"));
    }
    if !&args[1].ends_with(".txt") {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Second argument not valid (must end with .txt"));
    }
    match args.get(2) {
        Some(s) => {
            match s.to_lowercase().as_str() {
                "encrypt" => { 
                    println!("initiating encryption function");
                    // initialize files here or in the function?
                    // launch into encryption function
                }
                "decrypt" => {
                    println!("initiating decryption function");
                    // initialize functions here or in the function?
                    // launch into decryption function
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

    // Define variables for names, files, etc.
    let originalname = &args[0]; // should be defined by user in CLI later
    let copyname = &args[1]; // same as originalname note, should eventually be encrypted

    // check if originalname exists & is .txt (is this already done in the code above)
    // if exists, proceed. If not, exit 
    match fs::exists(originalname) {
        Ok(true) => {
            // Start process. Should this be a separate function for encrypt and decrypt, so functions can be called during the above code instead?
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

    // copy the file to another file
    // use OpenOption, so if copy doesn't exist, it can be created. Should it be overwritten?
    Ok(())
}

fn decrypt(original: std::fs::File, copy: std::fs::File) { // should copy be taken as an argument here, or only returned? Should these be std::fs::file or std::fs::OpenOptions?
    // Check if original exists. If not, throw an error. Should this error handling be done in the function, or before it is called? 
}

fn encrypt(original: std::fs::File, Copy: std::fs::File) {
    // Check if original exists. If not, throw an error. Should this error handling be done in the function, or before it is called?
}

// original and copy must be mutable