let user select their own password, or give option to generate one for them?
way to encrypt folders or strings/data instead of just files?
authentication tag
metadata
add pgp verification function
include more printlns for more information when using and recognizing what stage it's at, and when completed.
implement error handling when trying to write/read code during encryption, if it fails 
different types of encryption

1. let user input password, derive key from password
2. make nonce part of encrypted file data instead of separate input
3. Change naming scheme so its encrypted or decrypted depending on user action. 

understand the moon magic of types traits and implements

TODO FOR TOMORROW:
1. Change nonce to just be raw bytes
2. include salt detector for decryption, should be 16 bytes after the 12 nonce bytes
3. create the password input --> key
4. DECRYPTION MUST REMOVE FIRST 16+12 bytes during decryption process

encryption:
1. create the salt creation function
2. create the password+salt = key function
    salt should be initialized as a vec<u8> of size 16 
3. put salt and nonce bytes at beginning of encrypted file
4. delete thingy where it makes nonce.txt and key.txt
5. Write generated nonce and salt into encrypted file

make as website
    temp file sharing? Like, upload a file for next hour (discord server link + mediafire hybrid)
add pgp

PASSWORD BASED KEY
1. change CLI interface so it asks for a password instead of a key for both
    if encryption, derive key from password and then initiate encryption function
    if decryption, same thing?
2. finish function 

NONCE:
get rid of nonce: include as first x amount of characters when encrypting 
if operation is encrypt, add to beginning of file when new encrypted file has been created

if encryption, create a salt and stuff and use it and stuff

IN ORDER TO PREPEND, WRITE NONCE, THEN SALT, THEN THE REST OF THE DATA INTO THE U8 BEFORE CREATING THE NEW FILE 


Next: create salt creation function and stuff finish skibidi rizzler GYATTT
Return an error if the nonce or salt are found to be of mismatched lengths?

how to handle corrupted files or those where the nonce and salt aren't present and decryption is attempted? 

Is it easier to take the original file being worked on when locating nonce and salt, since that has already had the first 16+12 bytes taken out of it ?
    Are both PathBufs or do I need to change what thes kibid is 

return error if at least not long enough to cover salt+nonce? 
return error if the thingy they want to decrypt is already decrypted in the entry? 

delete original file if they ask to do so. Do via the &Path? 

Next: Work on encryption function, verify that .take() works as expected and that delete function path is correct 

add error handling for if the original file or folder already exists

way to hide the file type?