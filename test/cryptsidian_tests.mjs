/*
* mocha tests for cryptsidian.mjs
*/

//libs

import * as sourceCode from '../cryptsidian.mjs';
import * as assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

describe('getVaultFiles function', function(){
	let cwd = path.resolve();
	let tmp_vault_dir = path.join(cwd, 'tmpvaultdir');
	let result;

	before(function(){
		/* structure of tmp_vault_dir:
		a.md, b.md, c.md, a_copy.md
		sampledir
			d.md, anotherdir, emptydir
				emptydir> ., ..
				anotherdir> e.md, h.txt, thirddir
					thirddir> f.txt, g.txt
		*/		
		fs.mkdirSync(tmp_vault_dir);

		fs.writeFileSync(path.join(tmp_vault_dir, 'a_tmpfiletotestwith1010101010.md'), "This file is file a " + os.EOL);
		fs.writeFileSync(path.join(tmp_vault_dir, 'b_tmpfiletotestwith1010101010.md'), "This file is file b " + os.EOL);
		fs.writeFileSync(path.join(tmp_vault_dir, 'c_tmpfiletotestwith1010101010.md'), "This file is file c " + os.EOL);

		fs.mkdirSync(path.join(tmp_vault_dir, 'sampledir'));
		fs.writeFileSync(path.join(tmp_vault_dir, 'sampledir', 'd_tmpfiletotestwith1010101010.md'), "This file is file d " + os.EOL);

		fs.mkdirSync(path.join(tmp_vault_dir, 'sampledir', 'anotherdir'));
		fs.writeFileSync(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'e_tmpfiletotestwith1010101010.md'), "This file is file e " + os.EOL);
		fs.writeFileSync(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'h_tmpfiletotestwith1010101010.txt'), "This file is file h " + os.EOL);

		fs.mkdirSync(path.join(tmp_vault_dir, 'sampledir', 'emptydir'));

		fs.mkdirSync(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'thirddir'));
		fs.writeFileSync(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'thirddir', 'f_tmpfiletotestwith1010101010.txt'), "This file is file f " + os.EOL);
		fs.writeFileSync(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'thirddir', 'g_tmpfiletotestwith1010101010.txt'), "This file is file g " + os.EOL);

		result = sourceCode.getVaultFiles(tmp_vault_dir);

	})

	it('successfully finds all files, including in subdirs', function(){
		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'a_tmpfiletotestwith1010101010.md')), -1);
		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'b_tmpfiletotestwith1010101010.md')), -1);
		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'c_tmpfiletotestwith1010101010.md')), -1);

		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'sampledir', 'd_tmpfiletotestwith1010101010.md')), -1);

		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'e_tmpfiletotestwith1010101010.md')), -1);
		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'h_tmpfiletotestwith1010101010.txt')), -1);

		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'thirddir', 'f_tmpfiletotestwith1010101010.txt')), -1);
		assert.notStrictEqual(result.indexOf(path.join(tmp_vault_dir, 'sampledir', 'anotherdir', 'thirddir', 'g_tmpfiletotestwith1010101010.txt')), -1);
	})

	it("doesn't return files that aren't there", function(){
		assert.strictEqual(result.indexOf(path.join(tmp_vault_dir, 'doesnotexist10101010')), -1);

	})

	it("ignores dot files", function(){
		assert.strictEqual(result.indexOf(path.join(tmp_vault_dir, '..')), -1);
	})

	it("ignores empty directories", function(){
		const matches = result.filter(entry => entry.includes('emptydir'));
		assert.strictEqual(matches.length, 0);
	})

	after(function(){
		fs.rmSync(tmp_vault_dir, {recursive: true});
	})


})


describe('encryptFile function', function() {

	let tmp_file_path = path.normalize('./tmpfiletoencrypt95638.md'); //some filename unlikely to already exist
	let tmp_file_a_path = path.normalize('./a_tmpfileatocompare65836384784.md');
	let tmp_file_b_path = path.normalize('./b_tmpfileatocompare65836384784.md');

	before(function(){
		fs.writeFileSync(tmp_file_path, "This file is " + tmp_file_path + " \n");
		fs.writeFileSync(tmp_file_a_path, "This file is a.md");
		fs.writeFileSync(tmp_file_b_path, "This file is a.md");
		sourceCode.setUserSecretKey('password1234567890PASSWORD`~!@#$%^&*()[]{};:\'"/?.><,');
	})

	it('throws an exception if the file does not exist', function(){
		let file_path = path.normalize('./n7843iu23kjf783i2lefigblhiaef78aw3oi3rwi.doesnotexist');
		assert.throws(
			() => sourceCode.encryptFile(file_path),
			/.*no such file or directory.*/ //note this throw is really coming from getFileBuffer()
			);
	})

	it('overwrites the file', function(){
		sourceCode.encryptFile(tmp_file_path);
		let fd = fs.openSync(tmp_file_path, 'r+');
		let result = fs.readFileSync(fd);
		try{
			fs.close(fd);
		}
		catch (err) {
			throw new Error(err);
		}
		assert.notStrictEqual(result.toString('utf-8'), "This file is ./tmpfiletoencrypt95638.md \n");
	})

	it('outputs a different encryption when passed the same file twice', function(){
		sourceCode.encryptFile(tmp_file_a_path);
		let fd_a = fs.openSync(tmp_file_a_path, 'r+');
		let result_a = fs.readFileSync(fd_a);
		try{
			fs.close(fd_a);
		}
		catch (err){
			throw new Error(err);
		}

		sourceCode.encryptFile(tmp_file_b_path);
		let fd_b = fs.openSync(tmp_file_b_path, 'r+');
		let result_b = fs.readFileSync(fd_b);
		try{
			fs.close(fd_b);
		}
		catch (err){
			throw new Error(err);
		}

		assert.notStrictEqual(result_a.toString('utf-8'), result_b.toString('utf-8'));

	})

	//pending
	it('matches another implementation\'s aes-256-ctr encryption of a target string');
	//compare to a different implementation's aes-256-ctr encryption of some target string w/ same IV, salt, password for both

	//pending
	it('correctly uses the user supplied password to derive the secretKey for encryption');
	//check to see the user supplied password is actually being used - requires making IV constant, encrpyting a file,
	//and checking md5 of that encrypted file vs. what an end-to-end test of the app (with same static IV) outputs for that file
	//Spectron might be one way to automate this: https://www.wintellect.com/end-end-testing-electron-apps-spectron/

	after(function(){
		//tmp_file_path is used in decryptFile tests and removed after
		fs.rmSync(tmp_file_a_path);
		fs.rmSync(tmp_file_b_path);
	})

})

describe('decryptFile function', function() {
	let tmp_file_path = path.normalize('./tmpfiletoencrypt95638.md');

	before(function(){
		sourceCode.setUserSecretKey('password1234567890PASSWORD`~!@#$%^&*()[]{};:\'"/?.><,');
	})

	it('throws an exception if the file does not exist', function(){
		let file_path = path.normalize('./n7843iu23kjf783i2lefigblhiaef78aw3oi3rwi.doesnotexist');
		assert.throws(
			() => sourceCode.decryptFile(file_path),
			/.*no such file or directory.*/ 
			);
	})

	it('decrypts the file correctly', function(){
		sourceCode.decryptFile(tmp_file_path);
		let fd = fs.openSync(tmp_file_path, 'r+');
		let phrase = "This file is " + tmp_file_path + " \n";
		let buf = fs.readFileSync(fd);
		try{
			fs.close(fd);
		}
		catch (err) {
			throw new Error(err);
		}
		assert.strictEqual(buf.toString('utf-8'), "This file is " + path.normalize('./tmpfiletoencrypt95638.md') + " \n");
	})	

	after(function(){
		fs.rmSync(tmp_file_path);
	})


})

describe('stringSanitizer function', function(){
	it('rejects numbers', function(){
		assert.throws(function(){
			sourceCode.stringSanitizer(4)},
			/.*Password must be a string.*/);
	})

	it('rejects arrays', function(){
		assert.throws(function(){
			sourceCode.stringSanitizer([1, 2, 3])},
			/.*Password must be a string.*/);
	})

	it('rejects bools', function(){
		assert.throws(function(){
			sourceCode.stringSanitizer(true)},
			/.*Password must be a string.*/);
	})

	it('accepts input that has enough entropy', function(){
		let result = sourceCode.stringSanitizer('ihave13chars!jkihavewaymore');
		let testinput = 'ihave13chars!jkihavewaymore';
		testinput = testinput.normalize('NFC');
		assert.strictEqual(result, testinput);
	})

	it('correctly normalizes unicode input to NFC', function(){
		let string1 = '\u00F1' + 'ihave13chars!jkihavewaymore'; // \u00F1 is ñ
		let string2 = '\u006E\u0303' + 'ihave13chars!jkihavewaymore'; // \u006E\u0303 is also ñ
		string1 = sourceCode.stringSanitizer(string1);
		string2 = sourceCode.stringSanitizer(string2);
		assert.strictEqual(string1, string2);
	})

})

describe('hasEnoughEntropy function', function(){
	it('rejects calls with level < 64', function(){
		assert.throws(function(){
			sourceCode.hasEnoughEntropy('input', 63)},
			/.*called with < 64 bits of entropy.*/);
	})

	it('rejects inputs with entropy < level where password is < minlength', function(){
		assert.throws(function(){
			sourceCode.hasEnoughEntropy('input', 80)},
			{name: 'PasswordError'});
	})

	it('rejects inputs with entropy < level where password is >= minlength', function(){
		assert.throws(function(){
			sourceCode.hasEnoughEntropy('inputinput', 64)},
			{name: 'PasswordError'});
	})

	it('returns true when input entropy > level', function(){
		let result = sourceCode.hasEnoughEntropy('ihave13chars!jkihavewaymore', 80);
		assert.strictEqual(result, true);
	})
})

describe('keyDeriver function', function(){
	it('correctly handles null bytes in the middle of strings', function(){
		let result1 = sourceCode.keyDeriver('ihave13charsjkihavewaymore\0bar');
		let result2 = sourceCode.keyDeriver('ihave13charsjkihavewaymore');
		assert.notStrictEqual(result1, result2);
		//test will fail if the results are equal
		//results are equal if KDF implementation (scrypt) mistakes null byte for end of string marker
	})

	it('returns the same secretKey for the same password input', function(){
		let result1 = sourceCode.keyDeriver('ihave13chars!jkihavewaymore');
		let result2 = sourceCode.keyDeriver('ihave13chars!jkihavewaymore');
		assert.deepStrictEqual(result1, result2);
	})

	it('throws an error on null input', function(){
		assert.throws(function(){
			sourceCode.keyDeriver(null)},
			/.*bad input.*/);
	})


	it('throws an error on non-string input', function(){
		assert.throws(function(){
			sourceCode.keyDeriver(true)},
			/.*bad input.*/);
	})

})
