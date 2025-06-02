# File Encryption/Decryption Tool

This Rust program provides a command-line interface for encrypting and decrypting files using the AES-256-GCM algorithm. It securely handles file encryption with randomly generated keys and nonces, and supports password-based key derivation for decryption using Argon2.

**CURRENTLY NOT SECURE!!! THIS CODE HAS NOT BEEN TESTED OR THOUROUGHLY DEBUGGED. IF YOU USE IT, PLEASE ENSURE ANY IMPORTANT FILES HAVE BEEN BACKED UP, AND PLEASE DO NOT USE THIS FOR ANY FILES THAT DEMAND BATTLE-TESTED OR HIGH-GRADE ENCRYPTION.**

## Features

- **Encryption**: Encrypts a specified file using AES-256-GCM based on a user-selected password, generating a key, nonce and salt.
- **Decryption**: Decrypts a file using a provided password, nonce, and salt.
- **Secure Key Derivation**: Uses Argon2 for deriving encryption keys from passwords during decryption.
- **File Management**: Stores encrypted files, keys, and nonces in a dedicated `encrypted_files` directory within the user's documents folder.
- **Error Handling**: Comprehensive error handling for I/O, cryptographic operations, and file path issues.

## Future Features
- Website + Discord Bot Integration
- Different types of encryption
- Encrypt folders & raw data input
- Automatic password/pin generation
- Keyfile integration

## Prerequisites

- **Rust**: Ensure you have Rust installed (version 1.56 or later recommended).
- **Dependencies**: The program uses the following Rust crates:
  - `aes-gcm` for encryption/decryption.
  - `argon2` for password-based key derivation.
  - `dirs` for locating the documents directory.
  - `rpassword` for hiding the password when providing CLI input.

Install dependencies by including them in your `Cargo.toml`:

```toml
[dependencies]
rand = "0.9.1"
aes-gcm = { version = "0.10.3", features = ["std"] }
dirs = "6.0.0"
argon2 = "0.5.3"
rpassword = "7.4.0"

```

## Usage

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/AidanSky/file_encryption.git
   cd file_encryption
   ```

2. **Build the Program**:

   ```bash
   cargo build --release
   ```

3. **Run the Program**:

   - Using Cargo:
     ```bash
     cargo run --release
     ```

   - Using the compiled binary:
     ```bash
     ./target/release/file_encryption
     ```

4. **Follow Prompts**:

   - Enter the path to the file you want to encrypt or decrypt (e.g., `/path/to/file.txt`). You can get this for a file by right clicking on it, then selecting 'Copy as path'.
   - Choose the operation: `e` for encryption or `d` for decryption.
   - Choose whether or not you want the original file to be deleted.
   - Provide a password when prompted.

## Operation Details

### Encryption
- **Input**: 
  - A file path to the file you wish to encrypt.
  - A password for key derivation.
- **Process**:
  - Generates a 256-bit key based on inputted password + nonce + salt.
  - Encrypts the file using AES-256-GCM, with salt and nonce prepended to the newly encrypted version of the file.
  - Saves the encrypted file as `encrypted_<original_name>` in `~/Documents/encrypted_files/encryption_<original_name>`.
- **Output**:
  - Encrypted file: `~/Documents/encrypted_files/encryption_<original_name>/encrypted_<original_name>`

### Decryption
- **Input**:
  - A file path to the encrypted file.
  - A password for key derivation.
- **Process**:
  - Reads the nonce and salt from the beginning of the encrypted file.
  - Derives a key from the provided password and salt using Argon2.
  - Decrypts the file using AES-256-GCM with the derived key and nonce.
  - Saves the decrypted file as `decrypted_<original_name>` in `~/Documents/encrypted_files/encryption_<original_name>`.
- **Output**:
  - Decrypted file: `~/Documents/encrypted_files/encryption_<original_name>/decrypted_<original_name>`

## Error Handling

The program defines a custom `EncryptionError` enum to handle various errors, including:
- I/O errors (e.g., file not found, permission denied).
- Cryptographic errors (e.g., invalid key or nonce length).
- Path handling issues (e.g., invalid file names or directories).
- Argon2 key derivation errors.

Errors are displayed with descriptive messages to aid debugging.

## Security Considerations

- **Password Strength**: For decryption, use strong passwords to ensure robust key derivation with Argon2.
- **Hidden Password**: When inputting the password, the input will be hidden via rpassword.
- **File Overwrites**: The program checks for existing directories to prevent overwriting. Ensure the `encrypted_files` directory is backed up if needed.
- **Nonce and Salt**: Nonces are 96 bits (12 bytes), and salts are 128 bits (16 bytes), following AES-GCM recommendations.
- **Untested**: I have not currently thoroughly tested or debugged this program.

## Limitations

- The program assumes the encrypted file contains the nonce and salt at the beginning for decryption. Ensure the encrypted file is not modified manually.

## Future Improvements

- Support user-provided keys instead of random key generation.
- Add file integrity checks (e.g., HMAC) to detect tampering.
- Allow configuration of Argon2 parameters for key derivation.
- Allow file sharing, website integration, PGP signature verification, multiple encryption types & layering
- More customization for where files go and how duplicates are handled
- Check notes for more

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for bug reports or feature requests.
