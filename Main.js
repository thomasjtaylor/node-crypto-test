var log4js = require('log4js');
var crypto = require('crypto');
var pem = require('pem');
var fs = require('fs');

log4js.configure({
    appenders: [
        { type: 'console' },
        // { type: 'file', filename: 'runtime.log' }
    ]
});
var logger = log4js.getLogger('[Main]');
logger.setLevel('TRACE');

process.on('uncaughtException', function(err) {
  try {
    logger.error('Caught exception: ' + err);
    logger.error(err.stack);
  } catch (logEx) { } 
});

/* Windows: If OPENSSL_CONF environment variable is not set, set path to openssl.cfg */
if (process.env.OPENSSL_CONF==null) {
	process.env.OPENSSL_CONF='d:/dev/Programs/OpenSSL-Win64/bin/openssl.cfg';
	logger.debug('Set OpenSSL Conf: '+process.env.OPENSSL_CONF);
}


/** Create or read CA certificate/keys */
function getCA(callback) {
	var keyDir = 'keys/';
	var privateKeyFile = keyDir+'ca.privateKey',
		csrFile = keyDir+'ca.csr',
		certificateFile = keyDir+'ca.certificate',
		publicKeyFile = keyDir+'ca.publicKey';	
	// 1. create Certificate Authority
	var ca = {};
	
	// Create directory for keys/certificates
	if (!fs.existsSync(keyDir))
		fs.mkdirSync(keyDir);
		
	// 1a. Private Key

	function readPrivateKey(privateKeyFile, callback) { 
		logger.debug(privateKeyFile);
		fs.readFile(privateKeyFile, function(err, data) {	
			if (data) {
				logger.debug(privateKeyFile+' - Loaded');
				callback(data);
			} else {
				pem.createPrivateKey(2048, function(err, result) {
					logger.info('pem.createPrivateKey:');
					fs.writeFile(privateKeyFile, result.key, function(err) { logger.info('Wrote '+privateKeyFile); });
					callback(result.key);
				});
			}
		});
	}
	function readCSR(csrFile, callback) {	 
		logger.debug(csrFile);
		fs.readFile(csrFile, function(err, data) {
			if (data) {
				logger.debug(csrFile+' - Loaded');
				callback(data);
			} else {
				// 1b. Certi	ficate Signing Request (CSR)
				ca.csrOptions = {
					clientKey: ca.privateKey,
					keyBitsize: 2048,
					hash: 'sha512',
					country: "US",
					state: "FL",
					locality: "Miami",
					organization: "Example Corp",
					organizationUnit: "Development",
					commonName: "CA",
					altNames: ["Example.com CA", "example.com"],
					emailAddress: "email@example.com"
				};
				pem.createCSR(ca.csrOptions, function(err, result) {	
					logger.info('pem.createCSR: Options: '+JSON.stringify(ca.csrOptions));
					fs.writeFile(csrFile, result.csr, function(err) { logger.info('Wrote '+csrFile); });
					callback(result.csr);
				});
			}
		});
	}
	function readCertificate(certificateFile, callback) {
		logger.debug(certificateFile);
		fs.readFile(certificateFile, function(err, data) {
			if (data) {
				logger.debug(certificateFile+' - Loaded');
				callback(data);
			} else {
				// 1c. CA Certificate
				ca.certificateOptions = {
					serviceKey: ca.privateKey, // self-signed
					csr: ca.csr,
					days: 3650, // 10 years
				};
				pem.createCertificate(ca.certificateOptions, function(err,result) {	
					logger.info('pem.createCertificate: Options: '+JSON.stringify(ca.certificateOptions));
					// write CA Certificate to a file
					fs.writeFile(certificateFile, result.certificate, function(err) { logger.info('Wrote '+certificateFile); });
					callback(result.certificate);
				});
			}
		});
	}	
	function readPublicKey(publicKeyFile, callback) {	
		logger.debug(publicKeyFile);
		fs.readFile(publicKeyFile, function(err, data) {
			if (data) {
				logger.debug(publicKeyFile+' - Loaded');
				callback(data);
			} else 
				// 1d. CA Public Key
				pem.getPublicKey(ca.certificate, function(err, result) {
					logger.info('pem.getPublicKey:');
					fs.writeFile(publicKeyFile, result.publicKey, function(err) { logger.info('Wrote '+publicKeyFile); });
					callback(result.publicKey);
				});
		});
	}
	readPrivateKey(privateKeyFile, function(data) { 
		ca.privateKey = data;
		readCSR(csrFile, function(data) {
			ca.csr = data;
			readCertificate(certificateFile, function(data) {
				ca.certificate = data;
				readPublicKey(publicKeyFile, function(data) {
					ca.publicKey = data;
					callback(ca);
				});
			});
		});
	});
}

function signAndVerify(message, privateKey, certificate) {		
	logger.info('signAndVerify: '+message);					
	logger.debug('Hashes: '+crypto.getHashes());
	var hashAlgorithm = 'sha512',
		signAlgorithm = 'RSA-SHA512',
		messageEncoding = 'utf8',
		hashEncoding = 'base64';

	var hash = crypto.createHash(hashAlgorithm).update(message).digest(hashEncoding);
	console.log('messageDigest: '+hash);
	
	var sign = crypto.createSign(signAlgorithm).update(hash).sign(privateKey, hashEncoding);
	console.log('messageSignature: '+sign);
	
	var verify = crypto.createVerify(signAlgorithm).update(hash).verify(certificate, sign, hashEncoding);
	console.log('messageVerify(good): '+verify);
	
	verify = crypto.createVerify(signAlgorithm).update(hash).verify(certificate, '12'+sign, hashEncoding);
	console.log('messageVerify(bad sign): '+verify);
	verify = crypto.createVerify(signAlgorithm).update(hash+'1').verify(certificate, sign, hashEncoding);
	console.log('messageVerify(bad hash): '+verify);
}

function cipherAndDecipher(message, passphrase) {	
	logger.info('cipherAndDecipher: '+message);
	logger.debug('Ciphers: '+crypto.getCiphers());
	var algorithm = 'aes192',
		messageEncoding = 'utf8',
		cipherEncoding = 'buffer'; // use binary or hex to .join() chunks; use 'buffer' to .concat()
				
	var cipher = crypto.createCipher(algorithm, passphrase);
	cipher.setAutoPadding(auto_padding=true);
    var cipherChunks = [cipher.update(message, messageEncoding, cipherEncoding)];
    cipherChunks.push(cipher.final(cipherEncoding));
    console.log('Enciphered: ' + Buffer.concat(cipherChunks).toString('base64'));
    
    var decipher = crypto.createDecipher(algorithm, passphrase);	
    decipher.setAutoPadding(auto_padding=true);		    
    var plainText = decipher.update(Buffer.concat(cipherChunks), cipherEncoding, messageEncoding);
    plainText += decipher.final(messageEncoding);
    console.log("Deciphered: " + plainText);	
}

			    
function encryptAndDecrypt(message, publicKey, privateKey) {		
	logger.info('encryptAndDecrypt: '+message);
		    
    var encrypt = crypto.publicEncrypt(publicKey, new Buffer(message));			    
    console.log('Encrypt: ' + encrypt.toString('base64'));
    
    var decrypt = crypto.privateDecrypt(privateKey, encrypt);			    
    console.log('Decrypt: ' + decrypt);
};


getCA(function(ca) {
	pem.readCertificateInfo(ca.certificate, function(err, res) {
		logger.info('Cert Info: '+JSON.stringify(res));
		done = true;
	});
	
	signAndVerify("This is a short message used to test cryptography.", ca.privateKey, ca.certificate);
	cipherAndDecipher("This is a test message for encipher/decipher using a passphrase.", "This is a passphrase");
	encryptAndDecrypt("This is a test message for encrypt/decrypt using key pairs.", ca.publicKey, ca.privateKey);
});

