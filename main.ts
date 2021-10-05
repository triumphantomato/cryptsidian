import { App, Modal, Notice, Plugin, PluginSettingTab, Setting } from 'obsidian';

import * as cryptoSource from './cryptsidian.mjs'; //does this need to be converted w/ path for x-OS?
/*
// functions we're importing
import {hasEnoughEntropy, stringSanitizer, setUserSecretKey, keyDeriver, encryptFile, decryptFile, getVaultFiles, fileProcessor, getFileBuffer, openFile} from './tmpcryptsidian.mjs';

// variables we're importing
import {ALGORITHM, SALT, ENCRYPT, DECRYPT, KEY_LENGTH} from './tmpcryptsidian.js';
*/

interface MyPluginSettings {
	mySetting: string;
}

const DEFAULT_SETTINGS: MyPluginSettings = {
	mySetting: 'default'
}

export default class MyPlugin extends Plugin {
	settings: MyPluginSettings;

	async onload() {
		console.log('loading plugin');

		await this.loadSettings();

		this.addCommand({
			id: 'open-encrypt-modal',
			name: 'Open Encrypt Modal',
			
			checkCallback: (checking: boolean) => {
				let leaf = this.app.workspace.activeLeaf;
				if (leaf) {
					if (!checking) {
						new CryptoModal(this.app, 'Encrypt').open();
					}
					return true;
				}
				return false;
			}
			
		});

		this.addCommand({
			id: 'open-decrypt-modal',
			name: 'Open Decrypt Modal',
			
			checkCallback: (checking: boolean) => {
				let leaf = this.app.workspace.activeLeaf;
				if (leaf) {
					if (!checking) {
						new CryptoModal(this.app, 'Decrypt').open();
					}
					return true;
				}
				return false;
			}
			
		});
	}

	onunload() {
		console.log('unloading plugin');
	}

	async loadSettings() {
		this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}

}

class CryptoModal extends Modal {
	password  : string = null;
	operation : string = null;

	constructor(app: App, operation: string) {
		super(app);
		this.operation = operation;
	}

	onOpen() {

		// get vault dir
		let vault_dir = this.app.vault.adapter.getBasePath();

		//initiailze an empty DOM object to hold our modal
		let { contentEl } = this;
		contentEl.empty();

		//title - to let the user know which mode (encrypt/decrypt) they're in
		const titleEl = contentEl.createDiv();
		titleEl.style.fontWeight = 'bold';
		titleEl.style.marginBottom = '1em';
		titleEl.setText(`${this.operation}`);

		//notice - to let the user know which folder will be encrypted/decrypted
		const folderNotice = contentEl.createDiv();
		folderNotice.style.marginBottom = '1em';
		folderNotice.setText('This operation will apply to all files and folders in: ' + vault_dir);
		folderNotice.style.color = 'red';

		//notice - tell user not to open encrpyted files
		const corrputionNotice = contentEl.createDiv();
		corrputionNotice.style.marginBottom = '1.5em';
		corrputionNotice.setText('Do not open files with Obsidian after encrypting - they can become corrupted and irrecoverable. Always use the Decrypt command prior to re-opening files!');
		corrputionNotice.style.color = 'red';
		
		//make a div for user's pw input
        const inputPwContainerEl = contentEl.createDiv();
        const pwInputEl = inputPwContainerEl.createEl('input', { type: 'password', value: '' });
        pwInputEl.placeholder = 'Please enter your password';
        pwInputEl.style.width = '70%';
        pwInputEl.focus();

		//make a div for pw confirmation
		const confirmPwContainerEl = contentEl.createDiv();
		confirmPwContainerEl.style.marginTop = '1em';
		const pwConfirmEl = confirmPwContainerEl.createEl('input', { type: 'password', value: ''});
		pwConfirmEl.placeholder = 'Confirm your password';
		pwConfirmEl.style.width = '70%';

		//make a submit button for the crypto operation
		const confirmBtnEl = confirmPwContainerEl.createEl('button', { text: `${this.operation}` });
		confirmBtnEl.style.marginLeft = '1em';
		
		//message modal - to fire if passwords don't match
		const messageMatchEl = contentEl.createDiv();
		messageMatchEl.style.marginTop = '1em';
		messageMatchEl.style.color = 'red';
		messageMatchEl.setText('Passwords must match');
		messageMatchEl.hide();

		//message modal - to fire if either input is empty
		const messageEmptyEl = contentEl.createDiv();
		messageEmptyEl.style.marginTop = '1em';
		messageEmptyEl.style.color = 'red';
		messageEmptyEl.setText('Please enter your password in both boxes.');
		messageEmptyEl.hide();

		//message modal - to fire with cryptoSource.stringSanitizer() error message, if any
		const messageEl = contentEl.createDiv();
		messageEl.style.color = 'red';
		messageEl.style.marginTop = '1em';
		messageEl.hide();
		
		// check the input
		const pwChecker = (ev) => { // we use an arrow function to preserve access to the "this" we want
			ev.preventDefault();
			let good_to_go = false;
			
			// is either input field empty?
			if (pwInputEl.value == '' || pwInputEl.value == null || pwConfirmEl.value == '' || pwConfirmEl.value == null){
				good_to_go = false;
				messageEmptyEl.show();				
			}

			if (pwInputEl.value !== '' && pwInputEl.value !== null && pwConfirmEl.value !== '' && pwConfirmEl.value !== null){
				good_to_go = true;
				messageEmptyEl.hide();
			}

			// do both password inputs match?
			if (pwInputEl.value !== pwConfirmEl.value){
				good_to_go = false;
				messageMatchEl.show();
			}

			if (pwInputEl.value === pwConfirmEl.value){
				good_to_go = true;
				messageMatchEl.hide();
			}

			// is the user's password strong enough for crypto?
			if (good_to_go){
				try{
					messageEl.hide();
					good_to_go = Boolean(cryptoSource.stringSanitizer(pwInputEl.value)); 
					//true if user input had enough entropy, false otherwise
				}
				catch(error){
					good_to_go = false;
					messageEl.setText(error.message);
					messageEl.show();
				}
			}

			// if all checks pass, execute the crypto operation
			if (good_to_go){
				this.password = pwConfirmEl.value;
				cryptoSource.setUserSecretKey(this.password); //derive the secret key via scrypt from user's password

				this.app.workspace.detachLeavesOfType('markdown'); 
				// closes open notes to prevent post-encryption access, which can corrupt files and make them irrecoverable

				let files = cryptoSource.getVaultFiles(vault_dir); 
				cryptoSource.fileProcessor(files, this.operation.toUpperCase()); 

				this.close();
			}
		}

		//register the button's event handler
		confirmBtnEl.addEventListener('click', pwChecker);

		//allow enter to submit
		const enterSubmits = function(ev, value){
			if (
				( ev.code === 'Enter' || ev.code === 'NumpadEnter' )
				&& value.length > 0
				&& confirmBtnEl.disabled === false
			){
				ev.preventDefault();
				confirmBtnEl.click();
			}
		}
		pwInputEl.addEventListener('keypress', function(ev){ enterSubmits(ev, pwInputEl.value) });
		pwConfirmEl.addEventListener('keypress', function(ev){ enterSubmits(ev, pwInputEl.value) });

	}

	onClose() {
		let { contentEl } = this;
		contentEl.empty();
	}
}
