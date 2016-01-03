'use strict';

/**
 * @name encryptionService
 *
 * @author Markus Engel <m.engel188@gmail.com>
 * @version 1.2.0-beta.1
 *
 * @description
 * all encryption related bottom level functions that handle data encryption
 *
 */
(function() {

  var Promise = require('bluebird');
  var _ = require('lodash');

  var stableStringify = require('json-stable-stringify');

  var openpgp = require('openpgp');
  var crypto = require('crypto');

  // Constants //

  var ENCRYPTION_ALGORITHM = 'aes-256-cbc';
  var IV_LENGTH = 16;
  var AAC_LENGTH = 32;

  var VERSION_LENGTH = 1;

  var VERSION = 'a';
  var VERSION_BUF = new Buffer(VERSION);

  // Exported Service //

  module.exports = function() {
    var $ = {};

    /**
     * @name trimBuffer
     * @description trims a provided buffer to AAC_LENGTH in byte
     * when finished the old buffer is cleared so data is removed from RAM
     * @param {buffer} buffer that needs to be shortened
     * @return {buffer} trimmed buffer with length 32-Byte
     */
    var trimBuffer = function(buf) {
      var buf32 = new Buffer(AAC_LENGTH);
      buf.copy(buf32, 0, 0, AAC_LENGTH);

      clearBuffer(buf);
      return buf32;
    };

    /**
     * @name clearBuffer
     * @description clears a buffer so data is removed from RAM
     * @param {buffer} buffer that needs to be cleared
     */
    var clearBuffer = function(buf) {
      for (var i = 0; i < buf.length; i++) {
        buf[i] = 0;
      }
    };

    /**
     * @name deriveKey
     * @description derives a PBKDF2 key from given passwort with a length of 32 byte
     * @param {String} key we derive from
     * @param {String} method, is the result an encryption or signingkey
     * @return {Buffer} derived key as buffer
     */
    var deriveKey = function(master, method) {
      return new Promise(function(resolve, reject) {
        master = new Buffer(master);

        var hmac = crypto.createHmac('sha512', master);
        hmac.update(method);

        var key = new Buffer(hmac.digest());

        resolve(key);
      });
    };

    /**
     * @name generateKeyPair
     * @description generates an RSA public private key pair
     * the private key is automatically encrypted with the user pw using AES256-cbc
     * @param {String} format like this: 'firstname familyname <email>'
     * @param {String} user password
     * @param {Number} key length, either 1024 or 2048
     * @return {Array || error} array with the public private key pair or error
     */
    $.generateKeyPair = function(userIdent, password, numBits) {
      return new Promise(function(resolve, reject) {
        // create a strong passphrase from given password
        deriveKey(password, 'enc')
          .then(function(passphrase) {
            // trim to correct size
            passphrase = trimBuffer(passphrase);
            // parse required options
            var options = {
              numBits: numBits,
              userId: userIdent,
              passphrase: passphrase
            };

            // then generate the key pair
            return openpgp.generateKeyPair(options);
          })
          .then(function(keypair) {
            resolve(keypair);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name generateDocumentKey
     * @description generates a cryptographically strong random key
     * encoded as base64 string
     * @param {Number} key length, normally 32 or 64 bytes
     * @return {String || error} cryptographically strong random key or error
     */
    $.generateDocumentKey = function(length) {
      return new Promise(function(resolve, reject) {
        crypto.randomBytes(length, function(ex, buf) {
          // check if an error occured
          if (ex) {
            reject(ex);
            return;
          }

          // encode as base64 then resolve
          var token = buf.toString('base64');
          resolve(token);
        });
      });
    };

    /**
     * @name encryptDocumentKey
     * @description encrypts the documentKey using RSA
     * all provided publicKeys will be able to decode it
     * @param {String} the documentKey we want to encrypt
     * @param {Array || String} either an array of publicKeys or a string of 1 key
     * @return {String || error} the encrypted documentKey or error
     */
    $.encryptDocumentKey = function(documentKey, publicKeys) {
      return new Promise(function(resolve, reject) {
        var publicKeysProcessed = null;

        // if we have multiple publicKeys process them for encryption
        if (typeof publicKeys === 'object') {
          publicKeysProcessed = openpgp.key.readArmored(publicKeys[0]);

          publicKeys.shift();

          _.forEach(publicKeys, function(key, index) {
            var tempKey = openpgp.key.readArmored(key);
            publicKeysProcessed.keys.push(tempKey.keys[0]);
          });
        } else { // if we only have a single key as string process only this key
          publicKeysProcessed = openpgp.key.readArmored(publicKeys);
        }

        // encrypt the documentKey with all provided publicKeys
        openpgp.encryptMessage(publicKeysProcessed.keys, documentKey)
          .then(function(encryptedDocumentKey) {
            resolve(encryptedDocumentKey);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name decryptDocumentKey
     * @description decrypts the document key with provided privateKey
     * the private key is decrypted using the user password here
     * @param {String} encrypted private key
     * @param {String} user password
     * @param {String} the encrypted documentKey
     * @return {String || error} the decrypted documentKey or error
     */
    $.decryptDocumentKey = function(privateKey, password, encryptedDocumentKey) {
      return new Promise(function(resolve, reject) {
        // process the provided private key
        var privKey = openpgp.key.readArmored(privateKey).keys[0];

        deriveKey(password, 'enc')
          .then(function(passphrase) {
            // trim to correct size
            passphrase = trimBuffer(passphrase);
            // then decrypt the private key with the passphrase
            privKey.decrypt(passphrase);

            var encryptedDocKey = encryptedDocumentKey;
            // process the encrypted document key
            encryptedDocKey = openpgp.message.readArmored(encryptedDocKey);

            // then decrypt the encrypted document key with the decrypted private key
            return openpgp.decryptMessage(privKey, encryptedDocKey);
          })
          .then(function(decryptedDocumentKey) {
            resolve(decryptedDocumentKey);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name encryptDocument
     * @description encrypts the document using the documentKey
     * using cipheriv with AES256-cbc
     * @param {String} decrypted documentKey
     * @param {object} data to encrypt
     * @return {buffer || error} the encrypted document or error
     */
    $.encryptDocument = function(documentKey, data) {
      return new Promise(function(resolve, reject) {

        var text = JSON.stringify(data);
        var textBuffer = new Buffer(text, 'utf8');
        var key = new Buffer(documentKey, 'base64');

        // generate a iv
        $.generateDocumentKey(IV_LENGTH)
          .then(function(base64iv) {
            var iv = new Buffer(base64iv, 'base64');
            // create a cipheriv
            var cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);

            // encrypt the provided data
            try {
              cipher.write(textBuffer);
              cipher.end();
            } catch (ex) {
              reject(ex);
            }

            // add the version used, the iv and the encrypted data to the cipher text field
            var ct = Buffer.concat([VERSION_BUF, iv, cipher.read()]);
            resolve(ct);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name decryptDocument
     * @description decrypts the document
     * @param {String} decrypted documentKey
     * @param {object} data to decrypt
     * @return {Object || error} the decrypted document or error
     */
    $.decryptDocument = function(documentKey, encryptedData) {
      return new Promise(function(resolve, reject) {
        var key = new Buffer(documentKey, 'base64');

        // split the encrypted data into iv and cipher text
        var iv = encryptedData.slice(VERSION_LENGTH, VERSION_LENGTH + IV_LENGTH);
        var ct = encryptedData.slice(VERSION_LENGTH + IV_LENGTH, encryptedData.length);

        // then create a decipheriv
        var decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
        var decrypted = null;

        // try to decrypt the ct
        try {
          decipher.write(ct);
          decipher.end();
          decrypted = decipher.read();
        } catch (ex) {
          reject(ex);
        }

        // just in case
        if (decrypted) {
          // the decrypted data is in buffer format, resolve as JSON
          resolve(JSON.parse(decrypted));
        }
      });
    };

    /**
     * @name computeAC
     * @description creates an authentication cipher for the provided document
     * @param {object} the encrypted document we create an ac for
     * @param {String} decrypted documentKey
     * @param {array} all fields we want sign 
     * @param {String} optional version to be used, needed to reassemble old versions
     * @return {object || error} authCipher, object with full and basic ac or error
     * _ac: type buffer, the full ac with concated version and authenticated fields used
     * basicAC: type buffer, the ac, we use this for faster comparison
     */
    $.computeAC = function(doc, documentKey, authenticatedFields, version) {
      return new Promise(function(resolve, reject) {
        // check if version field is set, if not use global
        if (!version) {
          version = VERSION;
        }

        // check if fields to authenticate match the convention
        if (!(authenticatedFields instanceof Array)) {
          reject(new Error('fields must be an array'));
        }
        if (authenticatedFields.indexOf('_id') === -1) {
          reject(new Error('_id must be in array of fields to authenticate'));
        }
        if (authenticatedFields.indexOf('_ct') === -1) {
          reject(new Error('_ct must be in array of fields to authenticate'));
        }
        if (authenticatedFields.indexOf('hasAccess') === -1) {
          reject(new Error('hasAccess must be in array of fields to authenticate'));
        }
        if (authenticatedFields.indexOf('documentKey') === -1) {
          reject(new Error('documentKey must be in array of fields to authenticate'));
        }
        if (authenticatedFields.indexOf('_ac') !== -1) {
          reject(new Error('_ac cannot be in array of fields to authenticate'));
        }

        // collectionId is the document modelName
        var collectionId = doc.constructor.modelName;

        if (!collectionId) {
          reject(new Error('For authentication, each collection must have the model name as unique id.'));
        }

        // create the signingKey with documentKey as master
        deriveKey(documentKey, 'sig')
        .then(function(signingKey){

        // use the signingKey to create an HMAC-sha512 hash
        var hmac = crypto.createHmac('sha512', signingKey);

        // convert to regular object if possible in order to convert to the eventual mongo form which may be different than mongoose form
        // and only pick authenticatedFields that will be authenticated
        var objectToAuthenticate = _.pick((doc.toObject ? doc.toObject() : doc), authenticatedFields);
        var stringToAuthenticate = stableStringify(objectToAuthenticate);

        // add the collectionId, the version, the string and fields to authenticate to the HMAC hash
        hmac.update(collectionId);
        hmac.update(version);
        hmac.update(stringToAuthenticate);
        hmac.update(JSON.stringify(authenticatedFields));

        // digest the final hmac to buffer format
        var fullAuthenticationBuffer = new Buffer(hmac.digest());
        // trim the full acBuffer to AAC_LENGTH
        var basicAC = trimBuffer(fullAuthenticationBuffer);

        // add version, the basicAC and all authenticated fields to the full authentication cipher
        var authenticatedFieldsBuf = new Buffer(JSON.stringify(authenticatedFields));
        var _ac = Buffer.concat([VERSION_BUF, basicAC, authenticatedFieldsBuf]);

        var authCipher = {
          _ac: _ac,
          basicAC: basicAC
        };

        resolve(authCipher);
        });
      });
    };

    /**
     * @name reassembleAC
     * @description splits the _ac fields into parts used
     * @param {object} the document we reassamble the ac from
     * @return {object || error} reassabledAC
     * authenticatedFieldsUsed: type array, all fields we authenticated
     * versionUsed: type String, the version we used for authenticating
     * basicAC: tpye buffer, the plain authentication cipher
     */
    $.reassembleAC = function(doc) {
      return new Promise(function(resolve, reject) {
        // parse the authentication cipher from the document
        var acBuf = doc._ac.hasOwnProperty('buffer') ? doc._ac.buffer : doc._ac;
        // check if the length is correct, if not we can stop cause we know it was modified
        if (acBuf.length < VERSION_LENGTH + AAC_LENGTH + 2) {
          reject(new Error('_ac has been modified'));
        }

        // parse the version, basicAC and authenticated fields from the full authenticatin cipher
        var versionUsed = acBuf.slice(0, VERSION_LENGTH).toString();
        var basicAC = acBuf.slice(VERSION_LENGTH, VERSION_LENGTH + AAC_LENGTH);
        var authenticatedFieldsUsed = JSON.parse(acBuf.slice(VERSION_LENGTH + AAC_LENGTH, acBuf.length).toString());

        var reassembledAC = {
          authenticatedFieldsUsed: authenticatedFieldsUsed,
          versionUsed: versionUsed,
          basicAC: basicAC
        };

        resolve(reassembledAC);
      });
    };

    return $;
  };
})();