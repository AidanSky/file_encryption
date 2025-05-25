fn main() -> io::Result<()> {
    println!("--- File Encryption/Decryption Tool ---");

    let file_directory = loop {
        let input = read_user_input("Please enter the file directory: ");
        let path = PathBuf::from(&input);
        if path.is_dir() {
            println!("Directory selected: {}", path.display());
            break path;
        } else if path.exists() {
            println!("Error: '{}' exists but is not a directory. Please enter a valid directory.", path.display());
        } else {
            println!("Error: Directory '{}' does not exist. Please enter a valid directory.", path.display());
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

    let mut key: Option<String> = None;
    let mut nonce: Option<String> = None;

    // 3. If decrypt, then ask for key and nonce
    if operation == "decrypt" {
        key = Some(read_user_input("Please enter the key for decryption: "));
        nonce = Some(read_user_input("Please enter the nonce for decryption: "));
    }
}

fn read_user_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().expect("Failed to flush stdout");

    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input)
        .expect("Failed to read line");

    user_input.trim().to_string() // Trim whitespace and convert to owned String
}