'use strict';

/**
 * @name encryptionWrapper
 *
 * @author Markus Engel <m.engel188@gmail.com>
 * @version 1.0.0
 *
 * @description
 * wrapper that handles top level processing of encryption and sharing related functions
 *
 */
(function() {

  var Promise = require('bluebird');
  var mongoose = require('mongoose');

  var _fp = require('lodash-fp');
  var bufferEqual = require('buffer-equal-constant-time');

  var encrypt = require('./encryptionService')();

  module.exports = function() {
    var $ = {};

    /**
     * @name encryptDocument
     * @description function to ecrypt a document
     * @param {Mongoose document} doc the document to be encrypeted
     * @param {object} the decrypted document and signingkey
     * @param {object} encryptedFields the fields to be encrypted
     * @param {document object} object of data to be updated
     * @return {document || error} the encrypted document or error  
     */
    $.encryptDocument = function(doc, documentKey, encryptedFields, update) {
      return new Promise(function(resolve, reject) {
        // check if an update should be performed
        if (update || typeof update !== 'function') {
          // update all document values with provided update values
          _fp.forEach(function(value, key) {
            doc[key] = value;
          }, update);
        }

        var objectToEncrypt, val;

        // pick all keys that should be encrypted from the document
        // and temp store them in objectToEncrypt for later usage
        objectToEncrypt = _fp.pick(encryptedFields, doc);

        // only encrypt fields that are defined
        _fp.forEach(function(key, value) {
          val = objectToEncrypt[key];
          if (val === undefined) {
            delete objectToEncrypt[key];
          }
        }, objectToEncrypt);

        // encrypt the specified fields
        encrypt.encryptDocument(documentKey, objectToEncrypt)
          .then(function(encryptedDoc) {
            // store the encrypted fields in the _ct key of the document
            doc._ct = encryptedDoc;

            // reset the encryptedFields to undefined
            _fp.forEach(function(key, value) {
              doc[key] = undefined;
            }, encryptedFields);

            // encryption is finished so resolve the encrypted document
            resolve(doc);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name signDocument
     * @description function to sign a document
     * @param {Mongoose document} doc the document to be signed
     * @param {string} signingKey the user signingKey
     * @param {object} authenticatedFields for example {_id, _ct}
     * @param {string} modelName
     * @return {promise} the generated _ac key or error  
     */
    $.signDocument = function(doc, signingKey, authenticatedFields, modelName) {
      return new Promise(function(resolve, reject) {
        // create the authentication cipher
        encrypt.computeAC(doc, signingKey, authenticatedFields, modelName)
          .then(function(authCipher) {
            doc._ac = authCipher._ac;
            // computeAC is finished, resolve signed document
            resolve(doc);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name verifyDocument
     * @description function to verify the document singning
     * @param {Mongoose document} doc the document to be verified
     * @param {object} the decrypted document and signingkey
     * @return {true || error} true or error  
     */
    $.verifyDocument = function(doc, signingKey) {
      return new Promise(function(resolve, reject) {
        var reassembledAuthCipher;

        // split the _ac field into ac and fields used
        encrypt.reassembleAC(doc)
          .then(function(reassembledAC) {
            reassembledAuthCipher = reassembledAC;

            // compute the expected ac
            // with the authentication fields used for creating the actual one
            // and the document we have now
            return encrypt.computeAC(doc, signingKey, reassembledAC.authenticatedFieldsUsed);
          })
          .then(function(expectedAuthCipher) {
            // check if the expected basicAC matches the reassembled basicAC
            var authentic = bufferEqual(expectedAuthCipher.basicAC, reassembledAuthCipher.basicAC);

            // they match all is good continue
            if (authentic) {
              resolve(true);
            }
            // else throw an error
            return Promise.reject(new Error('Document not authentic'));
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name decryptDocument
     * @description function to decrypt an encrypted document
     * @param {Mongoose document} doc the document to be decrypted
     * @param {object} the decrypted document and signingkey
     * @return {document || error} the decrypted document or error  
     */
    $.decryptDocument = function(doc, documentKey) {
      return new Promise(function(resolve, reject) {
        var decipheredVal;

        // if either the _ct or _ac field is missing the document is corrupted
        // pass a generic error to hide implementation details
        if (!doc._ct || !doc._ac) {
          reject(new Error('failed due to an internal decryption error'));
        }

        // decrypt the _ct field
        encrypt.decryptDocument(documentKey, doc._ct)
          .then(function(decryptedDoc) {

            // parse the _ct field and insert the decrypted values back into the document
            _fp.forEach(function(value, key) {
              decipheredVal = decryptedDoc[key];

              // if the value is a buffer write value.data
              // else just put the value
              doc[key] = (_fp.isObject(decipheredVal) && decipheredVal.type === 'Buffer') ?
                decipheredVal.data : decipheredVal;

            }, decryptedDoc);

            // reset _ct and _ac fields to undefined when decryption is finished
            doc._ct = undefined;
            doc._ac = undefined;
            resolve(doc);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name shareDocument
     * @description function to share document permissions
     * @param {Mongoose shema object} UserModel shema
     * @param {Mongoose shema object} SharedModel the shema of the model to be shared
     * @param {object} the decrypted document and signingkeys as well as the owner _id
     * @param {mongo objectId} shareToId the id of the user who will be granted persmission to access the shared document
     * @param {mongo obhectId} sharedDocumentId the if of the document to be shared 
     * @return {promise resolve || error} "success" or error error 
     */
    $.shareDocument = function(UserModel, SharedModel, authentication, shareToId, sharedDocumentId) {
      return new Promise(function(resolve, reject) {
        var newEncryptedDocKey, sharedDocEncrypted;
        var publicKeys = [];

        // get the model we share
        SharedModel.findOneAsync({
            _id: sharedDocumentId
          })
          .then(function(sharedDoc) {
            sharedDocEncrypted = sharedDoc;

            // check if the model is shared with this user already
            if (sharedDocEncrypted.hasAccess.indexOf(shareToId) !== -1) {
              return Promise.reject(new Error('This User has access already'));
            } else { // else get all public keys of other users we shared this document with
              return UserModel.findAsync({
                  _id: {
                    $in: sharedDocEncrypted.hasAccess
                  }
                })
                .then(function(sharedToUsers) {
                  if (sharedToUsers && !_fp.isEmpty(sharedToUsers)) {
                    _fp.forEach(function(value, key) {
                      publicKeys.push(value.encryption.publicKey);
                    }, sharedToUsers);
                  }
                  // get the public key of the user we share our document with
                  return UserModel.findOne({
                    _id: shareToId
                  }, {
                    'encryption.publicKey': 1
                  });
                });
            }
          })
          .then(function(userTo) {
            // add the publicKey of the user we share to to the publicKeys array
            publicKeys.push(userTo.encryption.publicKey);

            // get the public key of the user we share from
            return UserModel.findOne({
              _id: authentication._id
            });
          }, {
            'encryption.publicKey': 1
          })
          .then(function(owner) {
            // push the public key of the document owner to the publicKeys array
            publicKeys.push(owner.encryption.publicKey);

            // encrypt the documentKey with all public keys that have access
            return encrypt.encryptDocumentKey(authentication.documentAccess[sharedDocEncrypted._id].documentKey, publicKeys);
          })
          .then(function(encryptedDocumentKey) {
            // temp store the newEncryptedDocumentKey for later use
            newEncryptedDocKey = encryptedDocumentKey;

            // decrypt the document we share
            return sharedDocEncrypted.decrypt(authentication);
          })
          .then(function(sharedDoc) {
            // if hasAccess exists, push the shareToId
            if (sharedDoc.hasAccess && sharedDoc.hasAccess.length >= 1) {
              sharedDoc.hasAccess.push(shareToId);
            } else { // else create a new array with the shareToId in it
              sharedDoc.hasAccess = [shareToId];
            }

            // overwrite the old encryptedDocumentKey with the newEncryptedDocumentKey 
            // access is granted to the additional user
            sharedDoc.documentKey = newEncryptedDocKey;

            // save the sharedDoc
            return sharedDoc.saveAsync({
              authentication: authentication
            });
          })
          .then(function() {
            resolve('success');
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name revokeAccess
     * @description function to revoke document access permissions
     * @param {Mongoose shema object} UserModel shema
     * @param {Mongoose shema object} SharedModel the shema of the model that is revoked from
     * @param {object} the decrypted document and signingkeys as well as the owner _id
     * @param {mongo objectId} revokeFromId the id of the user whose permissions will be revoked
     * @param {mongo obhectId} revokeFromSharedId the if of the document which should be no more readable 
     * @return {promise resolve || error} "success" or error 
     */
    $.revokeAccess = function(UserModel, SharedModel, authentication, revokeFromId, revokeFromSharedDocId) {
      return new Promise(function(resolve, reject) {
        var hasAccess, sharedDocEncrypted, newEncryptedDocumentKey;
        var publicKeys = [];

        // get the document owner
        UserModel.findOneAsync({
            _id: authentication._id
          }, {
            'encryption.publicKey': 1
          })
          .then(function(owner) {
            // push the public key of the document owner into the publicKeys array
            publicKeys.push(owner.encryption.publicKey);

            // get the model we revoke access from
            return SharedModel.findOne({
              _id: revokeFromSharedDocId
            });
          })
          .then(function(sharedDoc) {
            // temp save the sharedDocument for later use
            sharedDocEncrypted = sharedDoc;

            if (sharedDocEncrypted.hasAccess.indexOf(revokeFromId) === -1) {
              return Promise.reject(new Error('This User doesnt have access to this document'));
            }

            // temp save all users that still have access to the document
            // this includes removing the user that gets his access revoked
            hasAccess = [];
            _fp.forEach(function(value, index) {
              if (value.toString() !== revokeFromId.toString()) {
                hasAccess.push(value);
              }
            }, sharedDoc.hasAccess);

            // if no other user has access resolve our publicKeys array
            // that got our owner public key in it
            if (_fp.isEmpty(hasAccess)) {
              return Promise.resolve(publicKeys);
            } else { // else get user documents that have access
              return UserModel.findAsync({
                  _id: {
                    $in: hasAccess
                  }
                })
                .then(function(users) {
                  // push all public keys that still have access to our publicKeys array
                  _fp.forEach(function(value, key) {
                    publicKeys.push(value.encryption.publicKey);
                  }, users);

                  // return all public keys that have access still
                  return Promise.resolve(publicKeys);
                });
            }
          })
          .then(function(pKeys) {
            // encrypt the documentKey with all users that still have access
            return encrypt.encryptDocumentKey(authentication.documentAccess[sharedDocEncrypted._id].documentKey, pKeys);
          })
          .then(function(encryptedDocKey) {
            // temp store the newEncryptedDocumentKey
            newEncryptedDocumentKey = encryptedDocKey;

            // decrypt the sharedDocument
            return sharedDocEncrypted.decrypt(authentication);
          })
          .then(function(sharedDocumentDec) {
            // store the ids of all users that still have access 
            sharedDocumentDec.hasAccess = hasAccess;
            // overwrite the old encryptedDocumentKey with the newEncryptedDocumentKey 
            // access is granted to all users that still got access
            sharedDocumentDec.documentKey = newEncryptedDocumentKey;

            // save the sharedDoc
            return sharedDocumentDec.saveAsync({
              authentication: authentication
            });
          })
          .then(function() {
            resolve('success');
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name revokeAll
     * @description function to revoke access permissions for all user documents
     * @param {Mongoose shema object} UserModel shema
     * @param {Mongoose shema object} SharedModel the shema of the model that is revoked from
     * @param {object} the decrypted document and signingkeys as well as the owner _id
     * @return {object || error} a new token payload with updated doc/sigkeys or error error
     */
    $.revokeAll = function(UserModel, SharedModel, authentication) {
      return new Promise(function(resolve, reject) {
        var promises, encryptedSharedDocuments, newDocumentKeys, newSigningKeys, newEncryptedDocumentKeys, newEncryptedSigningKeys;

        // we need to create a new token payload with the newly generated document and signingkeys
        var newAuthentication = authentication;

        // get all shared documents
        SharedModel.findAsync({
            user_id: authentication._id
          })
          .then(function(encryptedSharedDocs) {
            // temp save encryptedSharedDocs for later use
            encryptedSharedDocuments = encryptedSharedDocs;
            promises = [];

            // create a new documentkey for each sharedDoc
            _fp.forEach(function(sharedDoc, index) {
              promises.push(encrypt.generateDocumentKey(32));
            }, encryptedSharedDocuments);

            return Promise.all(promises);
          })
          .then(function(docKeys) {
            // temp save new docKeys for later use
            newDocumentKeys = docKeys;

            promises = [];

            // create a new signingkey for each sharedDoc
            _fp.forEach(function(sharedDoc, index) {
              promises.push(encrypt.generateDocumentKey(64));
            }, encryptedSharedDocuments);

            return Promise.all(promises);
          })
          .then(function(sigKeys) {
            // temp save new signingKeys for later use
            newSigningKeys = sigKeys;

            // get the publicKey of the owner
            return UserModel.findOneAsync({
              _id: authentication._id
            }, {
              'encryption.publicKey': 1
            });
          })
          .then(function(owner) {
            promises = [];

            // encrypt each of the new documentkeys
            _fp.forEach(function(sharedDoc, index) {
              promises.push(encrypt.encryptDocumentKey(newDocumentKeys[index], owner.encryption.publicKey));
            }, encryptedSharedDocuments);

            return Promise.all(promises);
          })
          .then(function(docKeysEnc) {
            // temp save new docKeysEnc
            newEncryptedDocumentKeys = docKeysEnc;

            promises = [];

            // encrypt each of the new signingkeys
            _fp.forEach(function(sharedDoc, index) {
              promises.push(encrypt.encryptDocument(newDocumentKeys[index], {
                signingKey: newSigningKeys[index]
              }));
            }, encryptedSharedDocuments);

            return Promise.all(promises);
          })
          .then(function(sigKeysEnc) {
            // temp save new sigKeysEnc
            newEncryptedSigningKeys = sigKeysEnc;

            promises = [];

            // parse through every encrypted shared document
            _fp.forEach(function(encryptedSharedDoc, index) {
              // decrypt every encrypted shared document
              promises.push(encryptedSharedDoc.decrypt(authentication));
            }, encryptedSharedDocuments);

            // next step when decryption is finished for all shared documents
            return Promise.all(promises);
          })
          .then(function(decrSharedDocs) {
            promises = [];
            // parse through every decrypted shared document
            _fp.forEach(function(decrSharedDoc, index) {
              // replace old authentication with a new one for each shared document
              newAuthentication.documentAccess[decrSharedDoc._id] = {};
              newAuthentication.documentAccess[decrSharedDoc._id].documentKey = newDocumentKeys[index];
              newAuthentication.documentAccess[decrSharedDoc._id].signingKey = newSigningKeys[index];
              // reset hasAccess to empty array
              decrSharedDoc.hasAccess = [];
              // overwrite the old encryptedDocumentKey with the newEncryptedDocumentKey 
              // only the user has access to the shared documents now
              decrSharedDoc.documentKey = newEncryptedDocumentKeys[index];
              decrSharedDoc.signingKey = newEncryptedSigningKeys[index].toString('base64');
              // save all shared documents
              promises.push(decrSharedDoc.saveAsync({
                authentication: newAuthentication
              }));
            }, decrSharedDocs);

            // next step when saving is finished for all shared documents
            return Promise.all(promises);
          })
          .then(function(encrSharedDocs) {
            // resolve the new authentication so a new token can be signed
            resolve(newAuthentication);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    return $;
  };
})();