/* Cryptsidian
* By: triumphantomato
* https://github.com/triumphantomato
*/ 

/*
************************
************************
* Architecture Overview
************************
************************
// created with asciiflow.com

 ┌──────────────┐             ┌───────────────────┐       ┌────────────────────────┐
 │              │◄────────────┤                   │       │                        │
 │ Obsidian API │             │ API Functions     ├──────►│ Backend Functions      │
 │              ├────────────►│                   │       │        │   ▲           │
 │              │             │                   │       │        │   │           │
 │              │             │                   │       │        │   │           │
 │              │             │                   │       │        │   │           │
 │              │             │                   │       │        ▼               │
 │              │             │                   │       │  ┌─────────────────┐   │
 │              │             └───────────────────┘       │  │ Encrypt/Decrypt │   │
 │              │                                         │  │     Files       │   │
 │              │                                         │  │                 │   │
 │              │                                         │  │                 │   │
 │              │                                         │  │                 │   │
 │              │                                         │  │                 │   │
 │              │                                         │  └─────────────────┘   │
 │              │                                         │                        │
 │              │                                         └────────────────────────┘
 │              │
 └──────────────┘
*/

/*
* libraries
*/
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';

/*
* crypto primitives
*/
export const ALGORITHM = 'aes-256-ctr';
export const SALT = Buffer.alloc(32, '3170ebab43b9ccaaacbbb0ee72285a21c39fa324315db3ddcc11da1e3ff816e5', 'hex');
	//salt derived from crypto.randomBytes(32) - you can replace with your own, but will need to keep track
	//of this to decrypt your files in the future if you change it. Recommendation: leave it alone.

/*
* keywords
*/
export const ENCRYPT = 'ENCRYPT';
export const DECRYPT = 'DECRYPT';
export const KEY_LENGTH = 32; // length in bytes

/*
* global variables
*/
let secretKey; //will be derived from user input later 


/**
************************
************************
* API Functions
************************
************************
**/

/* all of these are implemented in the main.ts file, in onOpen() on class CryptoModal

* Registering Cryptsidian with the Obsidian Plugin API
* Prompting the user to enter their password for encryption/decryption. 
* Retrieving the path to the user's Obsidian vault
*/


/**
************************
************************
* Backend Functions
************************
************************
**/


/**
************************
* Backend: passwords
************************
**/


/**
* Takes a user-supplied string and checks for safety.
* @param {string} input - user supplied string
* @return {false|string} - false when input fails checks or string of user input if it passes.
**/
export function stringSanitizer( input ){
	if (typeof(input) !== 'string'){
		throw new Error("Password must be a string, received " + typeof(input) + " instead\n");
	}

	//deal with accents - normalize Unicode
	input = input.normalize('NFC'); 

	//validate entropy
	if (hasEnoughEntropy(input)){
		return input;
	}

	return false;
}

/**
* Takes a string and checks for sufficient entropy. 
* If a user's password has all character types (number, lower and uppercase, special chars), it will require 13 characters minimum at level=80.
* @param {string} input - input string
* @param {number} [level = 80] - entropy level in bits. 64 - okay but iffy, 80 - okay, 112 - recommended, 256 - probably quantum secure. Take these guidelines with a grain of salt and consult a cryptographer for your application.
* @return {bool} judgment - true if sufficient, false if not
**/
export function hasEnoughEntropy( input, level=80 ){
	if (level < 64){
		throw new Error('Function hasEnoughEntropy() called with < 64 bits of entropy. This is unsafe, aborting.\n');
	}
	
	let charspace = 0;
	let minlength = Math.ceil(level/Math.log2(10+26+26+32));

	if (level >= 64){

		//test entropy (via minlength)
		if (input.length < minlength){
			throw{
				name: "PasswordError",
				message: "Your password is not long enough. It must be " + minlength + " characters or longer.\n"
			}
		}

		//test entropy (via explicit entropy calculation)
		if (/\d+/g.test(input)) charspace += 10; //digits in charspace
		if (/[a-z]/g.test(input)) charspace += 26; //lowercase in charspace
		if (/[A-Z]/g.test(input)) charspace += 26; //uppercase in charspace
		if (/[`~!@#$%^&*()-=_+\[\]{};':"\\|,.<>\/?]/g.test(input)) charspace += 32; //special chars in charspace
		
		let entropy = input.length * Math.log2(charspace);

		if (entropy < level){
			throw{
				name: "PasswordError",
				message: "Your password is not strong enough. Try adding different kinds of characters, like numbers, special characters, or uppercase letters.\n"
			}
		}

		else if (entropy >= level){
			return true;
		}

		return false;

	}

	return false;
}


/**
************************
* Backend: keys
************************
**/


/**
* Takes a user password and sets the secretKey global variable by calling keyDeriver(password). 
* Is the isolation boundary between backend and frontend.
* @param {string} password - user password to derive encryption key from
* @returns <void>
**/
export function setUserSecretKey( password ){
	secretKey = Buffer.alloc(KEY_LENGTH); //zero-fills secretKey to be a buffer of length KEY_LENGTH
	secretKey = keyDeriver(password);
	return;
}

/**
* Takes an input string and returns a secret key of length key_length (default is value of constant KEY_LENGTH).
* @param {string} input
* @param {number} [key_length = KEY_LENGTH]
* @return {Buffer} secretKey
**/
export function keyDeriver( input, key_length=KEY_LENGTH ){
	if(input == null || typeof(input) !== 'string'){
		throw new Error("Function keyDeriver received bad input. Expected a non-null string.");
	}

	let password = stringSanitizer(input);
	if (password){
		secretKey = crypto.scryptSync(password, SALT, KEY_LENGTH);
		return secretKey;
	}
}

/**
* Checks to ensure secretKey is correctly set and then returns it. Accessing secretKey outside of this function is unsafe.
* @returns {Buffer} secretKey
**/

function getSecretKey( ){
	if (secretKey == null){ // (== null) checks null and undefined
		throw{
				name: "KeyError",
				message: "secretKey is null or undefined. Uh-oh.\n"
			}
	}

	if (secretKey.length !== KEY_LENGTH){
		throw{
			name: "KeyError",
			message: "secretKey is not the right length. Got: " + secretKey.length + " bytes, but expected: " + KEY_LENGTH + " bytes"
		}
	}

	return secretKey;
}


/**
**************************
* Backend: encrypt/decrypt
**************************
**/


/**
* Overwrites an encrypted version of the file to disk
* @param {string} file_path - location of file to encrypt
* @returns <void>
**/
export function encryptFile( file_path ){
	//get data and file descriptor
	let data = getFileBuffer(file_path);
	let fd = openFile(file_path);
	
	//generate IV
	let iv = crypto.randomBytes(16);

	//validate secretKey not empty
	let key = getSecretKey();

	//make a ciphertext
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
	const encrypted_data = Buffer.concat([cipher.update(data), cipher.final()]); 
	//cipher.final() not necessary for aes-256-ctr but this construciton should also
	//work with other algorithms
		
	//prepend IV and write encrypted data back to file
	fs.writeSync(fd, iv, 0, iv.length, 0); 
	fs.writeSync(fd, encrypted_data, 0, encrypted_data.length, iv.length);

	//cleanup
	fs.close(fd, (err) => {
		if (err){
			console.error("failed to close file descriptor when attempting to encrypt file: \n" + file_path + "\n in function encryptFile()\n");
			throw new Error(err);
		}
	});

}

/**
* Decrypts a file and writes it to disk, in place
* @param {string} file_path - file to decrypt
* @returns <void>
**/ 
export function decryptFile( file_path ){

	//get this to calculate cipher_data_length later
	let stats = fs.statSync(file_path); //must be done before opening the fd or it errors

	//get secretKey
	let key = getSecretKey();

	//get file descriptor
	let fd = openFile(file_path);

	//calculate cipher_data_length
	let cipher_data_length = (stats.size - 16); //in bytes, minus the 16-byte IV

	//we'll walk through the file to extract IV and then content instead of using getFileBuffer() helper function
	//read first 16 bytes for the IV
	let iv = Buffer.alloc(16);
	try{
		fs.readSync(fd, iv, 0, 16, null); //should advance file position to 16 bytes in
	}
	catch (err){
		console.error("Error using fs.readSync(fd, iv, 0, 16, null) to get the IV back");
		throw new Error(err);
	}

	//read the rest for the data
	let cipher_data = Buffer.alloc(cipher_data_length);
	fs.readSync(fd, cipher_data, 0, cipher_data_length, null); //should start the read from 16 bytes in

	//now make a decipher object and decrypt the file
	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
	const decrypted_data = Buffer.concat([decipher.update(cipher_data), decipher.final()]);

	//write the cleartext data back to file
	fs.writeSync(fd, decrypted_data, 0, decrypted_data.length, 0);

	//truncate the remaining crypto bytes from the overwritten file
	try{
		fs.ftruncateSync(fd, cipher_data_length); 
	}
	catch (err){
		console.error("Error truncating file after decryption in decryptFile(), for file: \n" + file_path);
		throw new Error(err);
	}

	//cleanup
	fs.close(fd, (err) => {
		if (err){
			console.error("failed to close file descriptor when attempting to decrypt file: \n" + file_path + "\n in function decryptFile()\n");
			throw new Error(err);
		}
	});

}


/**
************************
* Backend: files
************************
**/

/**
* Returns an fd or error for a file.
* @param {string} file_path
* @returns {number} fd
**/
export function openFile( file_path ){
	let fd;
	try{
		fd = fs.openSync(file_path, 'r+');
	}
	catch (err){
		throw new Error(err);
	}

	return fd;
}

/** 
* Returns the contents of a file as a buffer.
* @param {string} file_path - a single file path to read
* @return {Buffer} buf - buffer of an individual file
**/
export function getFileBuffer( file_path ){
	file_path = path.normalize(file_path);
	let buf;
	try{
		buf = fs.readFileSync(file_path);
	}
	catch (err){
		console.error("failed calling getFileBuffer() on file_path: " + file_path);
		throw new Error(err);
	}
	return buf;
}

/**
* Takes an array of filepaths and encrypts or decrypts them depending on operation.
* @param {Array}<string> file_array
* @param {string} operation
**/
export function fileProcessor( file_array, operation ){
	if (operation === 'ENCRYPT'){
		for (const file of file_array){
			encryptFile(file);
		}
		return;
	}
	if (operation === 'DECRYPT'){
		for (const file of file_array){
			decryptFile(file);
		}
		return;
	}
	else throw new Error("fileProcessor(file_array, operation) called with invalid operation argument. \n Got " + operation + ". Must be ENCRYPT or DECRYPT.");
}

/**
* Returns array of all files with absolute paths in Vault dir and all sub-dirs
* @param {string} vault - absolute path to the user's Obsidian vault
* @return {Array}<string> vault_files
**/
export function getVaultFiles( vault ){
	vault = path.normalize(vault);

	let vault_files = [];
	let files = [];

	try {
		files = fs.readdirSync(vault, {withFileTypes: true});
	} 
	catch (err) {
		console.error('failed calling fsreaddirSync(vault, {withFileTypes: true} on this directory: \'' + vault + '\'\n');
		throw new Error(err);
	}
	
	for (const file of files){
		if (file.name[0] === '.') continue; //skip dotfiles -- do i need to change this to be Windows compatible?

		if (file.isFile()){
			let absolutePath = path.resolve(vault, file.name);
			vault_files.push(absolutePath);
		
		}

		else if (file.isDirectory()){
			vault_files.push(...getVaultFiles(path.resolve(vault, file.name))); 
			//... is spread syntax unpacking the returned vault_files array from the recursed call
		}
	
	}

	return vault_files;

	//todo: make vault_files a TS array of only strings

}