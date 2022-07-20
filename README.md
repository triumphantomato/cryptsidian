## Cryptsidian: Encryption for Obsidian.md

Encrypt all files in your Obsidian.md Vault with a password.

---

**Three Warnings**
1. _Backup the Vault_ - before running the plugin make a backup to save your data.
2. _Remember your Password_ - files cannot be recovered without your password.
3. _File Corruption_ - Do not open files in Obsidian.md (or other app) after encrypting them. Contents can become corrupted and irrecoverable. The plugin auto-closes all open notes to avoid accidental corruption.

---

## 👋🏾 New Project: OpenRelay  

Want more privacy? Check out my [new project: OpenRelay](https://openrelay.typedream.app/), a community-built, privacy-first VPN with provably no logs! [Tech docs here](https://github.com/triumphantomato/openrelay).

---

### Cryptsidian Installation & Use
You can install the plugin via the Community Plugins tab within Obsidian by searching for "Cryptsidian".

Manual Installation: Copy over main.js and manifest.json (from Releases) to your vault in this location: `VaultFolder/.obsidian/plugins/cryptsidian/`.

Git Clone: `git clone` this repository into `VaultFolder/.obsidian/plugins/cryptsidian` and `npm install` and `npm run dev`.

**Use:** open the command palette (cmd + P on mac) and type "cryptsidian" to bring up the encrypt and decrypt modals. To encrypt, select the encrypt modal and enter your password. To decrypt, select the decrypt modal and enter the same password. 

If you use different passwords for encryption and decryption, your files will become corrupted.

Files remain encrypted (or decrypted) after the Obsidian app closes.

---

### Usability
This plugin makes it dead simple to encrypt your vault with a user selected password, including all notes and files (e.g. attachments) in the vault directory. Useful for single device, multiple user situations, like a family computer or a shared computer lab.

It is desktop-only and has been tested on OSX and Linux. It should work on Windows but has not been tested.

This plugin has not gone through an independent security audit and should not be relied upon for critical security applications.

Future changes to the Obsidian API may break this plugin. Forward compatibility is not guaranteed.

---

### Technical Notes
Files are encrypted and overwritten in-place on disk.

Encryption used is `aes-256-ctr`. A reasonable improvement would be using GCM instead to take advantage of AEAD.

Salt is static in the source code. IV is unique and random (and pre-pended to the file on disk). PBKDF is `scrypt` with default parameters, from the `Node.js crypto` API.

Password is required to posess sufficient entropy, but you can change the amount of entropy required in the `hasEnoughEntropy` function.

The backend functions are all in `cryptsidian.mjs`. The frontend interaction is in `main.ts`.

Unit tests can be run using `mocha` with `npm install` then `npm test`.

Code is well commented for readability. 




