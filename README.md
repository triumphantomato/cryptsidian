## Cryptsidian: Encryption for Obsidian.md

Encrypt all files in your Obsidian.md Vault with a password.

**Three Warnings**
1. _Backup the Vault_ - before running the plugin make a backup to save your data.
2. _Remember your Password_ - files cannot be recovered without your password.
3. _File Corruption_ - Do not open files in Obsidian.md (or other app) after encrypting them. Contents can become corrupted and irrecoverable. The plugin auto-closes all open notes to avoid accidental corruption.

### Installation
Manual: Copy over main.js, cryptsidian.mjs, and manifest.json to your vault in this location: `VaultFolder/.obsidian/plugins/cryptsidian/`.

Git Clone: `git clone` this repository into `VaultFolder/.obsidian/plugins/cryptsidian`.

### Usability
This plugin is desktop-only and has been tested on OSX and Linux. It should work on Windows but has not been tested.

This plugin has not gone through an independent security audit and should not be relied upon for critical security applications.

### Technical Notes
Files are encrypted and overwritten in-place on disk.

Encryption used is `aes-256-ctr`. A reasonable improvement would be using GCM instead to take advantage of AEAD.

Salt is static in the source code. IV is unique and random (and pre-pended to the file on disk). PBKDF is `scrpyt` with default parameters, from the `Node.js crpyto` API.

Password is required to posess sufficient entropy, but you can change the amount of entropy required in the `hasEnoughEntropy` function.

The backend functions are all in `cryptsidian.mjs`. The frontend interaction is in `main.ts`.

Unit tests can be run using `mocha` with `npm install` then `npm test`.

Code is well commented for readability. 




