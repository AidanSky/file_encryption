let user select their own password, or give option to generate one for them?
give option to delete the original file?
fix usage of unwrap
way to encrypt folders or strings/data instead of just files?
custom error enum
authentication tag
metadata
add pgp verification function
include more printlns for more information when using and recognizing what stage it's at, and when completed.
implement error handling when trying to write/read code during encryption, if it fails 

1. let user input password, derive key from password
2. make nonce part of encrypted file data instead of separate input
3. Change naming scheme so its encrypted or decrypted depending on user action. 

understand the moon magic of types traits and implements




PASSWORD BASED KEY
1. change CLI interface so it asks for a password instead of a key for both
    if encryption, derive key from password and then initiate encryption function
    if decryption, same thing?
2. finish function 