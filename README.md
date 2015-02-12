# node-crypto-test
Generation and use of PEM certificates for encryption and signing using Node.js crypto and the PEM node module.

Uses: 
* Node v0.12.0
* [Crypto](http://nodejs.org/api/crypto.html) - for encryption/decryption, hash/sign/verify
* [PEM](https://github.com/andris9/pem) - for generation of certificates
* [log4js](https://github.com/nomiddlename/log4js-node) - for logging
* [fs](http://nodejs.org/api/fs.html) - for saving certificates/keys to files

OS: Windows 8.1 x64
* Requires OpenSSL

# Usage
> node Main.js

## Key Generation
1. Loads or Generates Private Key (keys/ca.privateKey)
2. Loads or Generates CSR (keys/ca.csr)
3. Loads or Generates Certificate (keys/ca.certificate)
4. Loads or Generates Public Key (keys/ca.publicKey)

## Tests
1. Sign and Verify using privateKey and certificate
2. Cipher and Decipher using passphrase
3. Encrypt and Decrypt using privateKey and publicKey
