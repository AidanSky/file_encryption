# File Encryption/Decryption Tool

This Rust program provides a command-line interface for encrypting and decrypting files using the AES-256-GCM algorithm. It securely handles file encryption with randomly generated keys and nonces, and supports password-based key derivation for decryption using Argon2.

Currently, main.rs is non-functioning as I am making several significant changes. In the future, I plan for this to be a secure web app. 
ogversion.rs is functioning, so you can use that if you would like in the meantime.

**CURRENTLY NOT SECURE!!! DO NOT USE EITHER MAIN.RS OR OGVERSION.RS TO STORE ANYTHING THAT DEMANDS GENUINE SECURITY. OGVERSION.RS STORES BOTH THE KEY AND NONCE IN PLAINTEXT (BAD!!!) AND NEITHER ARE BATTLE-TESTED AT ALL!!!**

## Features

- **Encryption**: Encrypts a specified file using AES-256-GCM, generating a random key and nonce.
- **Decryption**: Decrypts a file using a provided password, nonce, and salt.
- **Secure Key Derivation**: Uses Argon2 for deriving encryption keys from passwords during decryption.
- **File Management**: Stores encrypted files, keys, and nonces in a dedicated `encrypted_files` directory within the user's documents folder.
- **Error Handling**: Comprehensive error handling for I/O, cryptographic operations, and file path issues.

## Prerequisites

- **Rust**: Ensure you have Rust installed (version 1.56 or later recommended).
- **Dependencies**: The program uses the following Rust crates:
  - `aes-gcm` for encryption/decryption.
  - `argon2` for password-based key derivation.
  - `hex` and `base64` for encoding keys and nonces.
  - `dirs` for locating the documents directory.

Install dependencies by including them in your `Cargo.toml`:

```toml
[dependencies]
aes-gcm = "0.10"
argon2 = "0.5"
hex = "0.4"
base64 = "0.22"
dirs = "5.0"
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
   ```bash
   cargo run --release
   ```

4. **Follow Prompts**:
   - Enter the path to the file you want to encrypt or decrypt (e.g., `/path/to/file.txt`).
   - Choose the operation: `e` for encryption or `d` for decryption.
   - Provide a password when prompted (required for decryption).

## Operation Details

### Encryption
- **Input**: A file path to the file you wish to encrypt.
- **Process**:
  - Generates a random 256-bit key and a 96-bit nonce using `OsRng`.
  - Encrypts the file using AES-256-GCM.
  - Saves the encrypted file as `encrypted_<original_name>` in `~/Documents/encrypted_files/encryption_<original_name>`.
  - Creates `key.txt` and `nonce.txt` containing the key and nonce in both hex and base64 formats.
- **Output**:
  - Encrypted file: `~/Documents/encrypted_files/encryption_<original_name>/encrypted_<original_name>`
  - Key file: `~/Documents/encrypted_files/encryption_<original_name>/key.txt`
  - Nonce file: `~/Documents/encrypted_files/encryption_<original_name>/nonce.txt`

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

- **Key Storage**: Keys and nonces are stored in plain text (`key.txt` and `nonce.txt`). Securely manage these files or consider modifying the program to use a more secure storage mechanism.
- **Password Strength**: For decryption, use strong passwords to ensure robust key derivation with Argon2.
- **File Overwrites**: The program checks for existing directories to prevent overwriting. Ensure the `encrypted_files` directory is backed up if needed.
- **Nonce and Salt**: Nonces are 96 bits (12 bytes), and salts are 128 bits (16 bytes), following AES-GCM recommendations.

## Limitations

- The program assumes the encrypted file contains the nonce and salt at the beginning for decryption. Ensure the encrypted file is not modified manually.
- Password input is not masked in the terminal for simplicity. Consider using a crate like `rpassword` for hidden input.
- The decryption process expects the nonce and salt to be prepended to the encrypted file, which is not implemented in the current encryption function.

## Future Improvements

- Prepend nonce and salt to the encrypted file during encryption to streamline decryption.
- Mask password input for better security.
- Support user-provided keys instead of random key generation.
- Add file integrity checks (e.g., HMAC) to detect tampering.
- Allow configuration of Argon2 parameters for key derivation.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for bug reports or feature requests.
