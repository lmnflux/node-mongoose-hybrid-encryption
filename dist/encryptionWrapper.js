'use strict';

/**
 * @name encryptionWrapper
 *
 * @author Markus Engel <m.engel188@gmail.com>
 * @version 1.2.1-beta.2
 *
 * @description
 * wrapper that handles top level processing of encryption and sharing related functions
 *
 */
(function() {

  var Promise = require('bluebird');
  var mongoose = require('mongoose');

  var _ = require('lodash');
  var bufferEqual = require('buffer-equal-constant-time');

  var encrypt = require('./encryptionService')();

  module.exports = function() {
    var $ = {};

    /**
     * @name parseAsync
     * @description helper function to check if given schema is promisified
     * @param {Mongoose shema object} shema
     * @return {Mongoose shema object} the promisified schema  
     */
    function parseAsync(shema) {
      // if it is already promisified return it
      if (shema.findOneAsync) {
        return shema;
      }
      // else promisify and return it
      Promise.promisifyAll(shema);
      Promise.promisifyAll(shema.prototype);
      return shema;
    }

    /**
     * @name encryptDocument
     * @description function to ecrypt a document
     * @param {Mongoose document} doc the document to be encrypeted
     * @param {String} the decrypted documentKey
     * @param {object} encryptedFields the fields to be encrypted
     * @param {document object} object of data to be updated
     * @return {document || error} the encrypted document or error  
     */
    $.encryptDocument = function(doc, documentKey, encryptedFields, update) {
      return new Promise(function(resolve, reject) {
        // check if an update should be performed
        if (update || typeof update !== 'function') {
          // update all document values with provided update values
          _.forEach(update, function(value, key) {
            doc[key] = value;
          });
        }

        var objectToEncrypt, val;

        // pick all keys that should be encrypted from the document
        // and temp store them in objectToEncrypt for later usage
        objectToEncrypt = _.pick(doc, encryptedFields);

        // only encrypt fields that are defined
        _.forEach(objectToEncrypt, function(key, value) {
          val = objectToEncrypt[key];
          if (val === undefined) {
            delete objectToEncrypt[key];
          }
        });

        // encrypt the specified fields
        encrypt.encryptDocument(documentKey, objectToEncrypt)
          .then(function(encryptedDoc) {
            // store the encrypted fields in the _ct key of the document
            doc._ct = encryptedDoc;

            // reset the encryptedFields to undefined
            _.forEach(encryptedFields, function(key, value) {
              doc[key] = undefined;
            });

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
     * @param {String} decrypted documentKey
     * @param {object} authenticatedFields for example {_id, _ct}
     * @return {promise} the generated _ac key or error  
     */
    $.signDocument = function(doc, documentKey, authenticatedFields) {
      return new Promise(function(resolve, reject) {
        // create the authentication cipher
        encrypt.computeAC(doc, documentKey, authenticatedFields)
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
     * @param {String} the decrypted documentkey
     * @return {true || error} true or error  
     */
    $.verifyDocument = function(doc, documentKey) {
      return new Promise(function(resolve, reject) {
        var reassembledAuthCipher;

        // split the _ac field into ac and fields used
        encrypt.reassembleAC(doc)
          .then(function(reassembledAC) {
            reassembledAuthCipher = reassembledAC;

            // compute the expected ac
            // with the authentication fields used for creating the actual one
            // and the document we have now
            return encrypt.computeAC(doc, documentKey, reassembledAC.authenticatedFieldsUsed, reassembledAC.versionUsed);
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
     * @param {String} the decrypted documentKey
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
            _.forEach(decryptedDoc, function(value, key) {
              decipheredVal = decryptedDoc[key];

              // if the value is a buffer write value.data
              // else just put the value
              doc[key] = (_.isObject(decipheredVal) && decipheredVal.type === 'Buffer') ?
                decipheredVal.data : decipheredVal;

            });

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
     * @param {Mongoose shema} UserModel shema
     * @param {object} the decrypted documentkeys as well as the owner _id
     * @param {Mongoose objectId} shareToId the id of the user who will be granted persmission to access the shared document
     * @param {Mongoose document} sharedDocumentEncrypted the document to be shared
     * @return {promise resolve || error} "success" or error error 
     */
    $.shareDocument = function(UserModel, authentication, shareToId, sharedDocEncrypted) {
      return new Promise(function(resolve, reject) {
        var newEncryptedDocKey;
        var publicKeys = [];

        // parse the UserModel to check if it is promisified or not
        UserModel = parseAsync(UserModel);

        // check if the model is shared with this user already
        if (sharedDocEncrypted.hasAccess.indexOf(shareToId) !== -1) {
          return Promise.reject(new Error('This User has access already'));
        }

        // if user doesnt have access get all public keys of other users we shared this document with
        UserModel.findAsync({
            _id: {
              $in: sharedDocEncrypted.hasAccess
            }
          })
          .then(function(sharedToUsers) {
            // check if there are users that have access, if yes add their public keys
            if (sharedToUsers && !_.isEmpty(sharedToUsers)) {
              _.forEach(sharedToUsers, function(value, key) {
                publicKeys.push(value.encryption.publicKey);
              });
            }
            // get the public key of the user we share our document with
            return UserModel.findOne({
              _id: shareToId
            }, {
              'encryption.publicKey': 1
            });
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
            return encrypt.encryptDocumentKey(authentication.documentAccess[sharedDocEncrypted._id], publicKeys);
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
     * @param {Mongoose shema} UserModel shema
     * @param {object} the decrypted documentkeys as well as the owner _id
     * @param {Mongoose objectId} revokeFromId the id of the user whose permissions will be revoked
     * @param {Mongoose document} sharedDocEncrypted the document access should be removed from
     * @return {promise resolve || error} "success" or error 
     */
    $.revokeAccess = function(UserModel, authentication, revokeFromId, sharedDocEncrypted) {
      return new Promise(function(resolve, reject) {
        var hasAccess, newEncryptedDocumentKey, newAuthentication;
        var publicKeys = [];

        // we need to create a new token payload for the newly generated documentkey
        newAuthentication = authentication;

        // parse the UserModel to check if it is promisified or not
        UserModel = parseAsync(UserModel);

        // get the document owner
        UserModel.findOneAsync({
            _id: authentication._id
          }, {
            'encryption.publicKey': 1
          })
          .then(function(owner) {
            // push the public key of the document owner into the publicKeys array
            publicKeys.push(owner.encryption.publicKey);

            if (sharedDocEncrypted.hasAccess.indexOf(revokeFromId) === -1) {
              return Promise.reject(new Error('This User doesnt have access to this document'));
            }

            // temp save all users that still have access to the document
            // this includes removing the user that gets his access revoked
            hasAccess = [];
            _.forEach(sharedDocEncrypted.hasAccess, function(value, index) {
              if (value.toString() !== revokeFromId.toString()) {
                hasAccess.push(value);
              }
            });

            // if no other user has access resolve our publicKeys array
            // that got our owner public key in it
            if (_.isEmpty(hasAccess)) {
              return Promise.resolve(publicKeys);
            } else { // else get user documents that have access
              return UserModel.findAsync({
                  _id: {
                    $in: hasAccess
                  }
                })
                .then(function(users) {
                  // push all public keys that still have access to our publicKeys array
                  _.forEach(users, function(value, key) {
                    publicKeys.push(value.encryption.publicKey);
                  });

                  // return all public keys that have access still
                  return Promise.resolve(publicKeys);
                });
            }
          })
          .then(function(pKeys) {
            // temp save the resolved pKeys for later use
            publicKeys = pKeys;
            // generate a new document key
            return encrypt.generateDocumentKey(32);
          })
          .then(function(documentKey) {
            // replace the old document key with the new one in the newAuthentication
            newAuthentication.documentAccess[sharedDocEncrypted._id] = documentKey;

            // encrypt the documentKey with all users that still have access
            return encrypt.encryptDocumentKey(newAuthentication.documentAccess[sharedDocEncrypted._id], publicKeys);
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
            // check if session management is allowed, if remove key from new session payload
            if (!sharedDocEncrypted.allowSession) {
              delete newAuthentication.documentAccess[sharedDocEncrypted._id];
            }
            // resolve the new authentication so a new token with the changed payload can be signed
            resolve(newAuthentication);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name revokeAll
     * @description function to revoke document access permissions of all users on given document
     * @param {Mongoose shema} UserModel shema
     * @param {object} the decrypted documentkeys as well as the owner _id
     * @param {Mongoose document} revokeFromSharedId the id of the document that shouldnt be shared anymore
     * @return {object || error} a new token payload with updated docKey or error
     */
    $.revokeAll = function(UserModel, authentication, sharedDocEncrypted) {
      return new Promise(function(resolve, reject) {
        var publicKey, hasAccess, newAuthentication, sharedDocDecrypted, newEncryptedDocumentKey;

        // we need to create a new token payload for the newly generated documentkey
        newAuthentication = authentication;

        // parse the UserModel to check if it is promisified or not
        UserModel = parseAsync(UserModel);

        // get the document owner
        UserModel.findOneAsync({
            _id: authentication._id
          }, {
            'encryption.publicKey': 1
          })
          .then(function(owner) {
            // temp store the owners public key for later use
            publicKey = owner.encryption.publicKey;

            return sharedDocEncrypted.decrypt(authentication);
          })
          .then(function(sharedDocDecr) {
            // temp save sharedDocDecrypted for later use
            sharedDocDecrypted = sharedDocDecr;

            // generate a new document key
            return encrypt.generateDocumentKey(32);
          })
          .then(function(docKey) {
            // replace the old document key with the new one in the newAuthentication
            newAuthentication.documentAccess[sharedDocDecrypted._id] = docKey;

            // encrypt the documentKey with the owners publicKey
            return encrypt.encryptDocumentKey(newAuthentication.documentAccess[sharedDocDecrypted._id], publicKey);
          })
          .then(function(encryptedDocKey) {
            // temp store the newEncryptedDocumentKey
            newEncryptedDocumentKey = encryptedDocKey;

            // store the ids of all users that still have access 
            sharedDocDecrypted.hasAccess = [];
            // overwrite the old encryptedDocumentKey with the newEncryptedDocumentKey
            // access is granted only to the owner now
            sharedDocDecrypted.documentKey = newEncryptedDocumentKey;

            // save the sharedDoc
            return sharedDocDecrypted.saveAsync({
              authentication: newAuthentication
            });
          })
          .then(function() {
            // check if session management is allowed, if remove key from new session payload
            if (!sharedDocEncrypted.allowSession) {
              delete newAuthentication.documentAccess[sharedDocEncrypted._id];
            }
            // resolve the new authentication so a new token with the changed payload can be signed
            resolve(newAuthentication);
          })
          .catch(function(err) {
            reject(err);
          });
      });
    };

    /**
     * @name resetAccessPermissions
     * @description function to reset access permissions for every shared document of given type
     * @param {Mongoose shema} UserModel shema
     * @param {Mongoose shema} SharedModel the shema of the model that is revoked from
     * @param {object} the decrypted documentKeys as well as the owner _id
     * @return {object || error} a new token payload with updated docKeys or error
     */
    $.resetAccessPermissions = function(UserModel, SharedModel, authentication) {
      return new Promise(function(resolve, reject) {
        var promises, encryptedSharedDocuments, newDocumentKeys, newEncryptedDocumentKeys;

        // we need to create a new token payload with the newly generated documentkeys
        var newAuthentication = authentication;

        // parse the UserModel and the SharedModel to check if they are promisified or not
        UserModel = parseAsync(UserModel);
        SharedModel = parseAsync(SharedModel);

        // get all shared documents
        SharedModel.findAsync({
            user_id: authentication._id
          })
          .then(function(encryptedSharedDocs) {
            // temp save encryptedSharedDocs for later use
            encryptedSharedDocuments = encryptedSharedDocs;
            promises = [];

            // create a new documentkey for each sharedDoc
            _.forEach(encryptedSharedDocuments, function(sharedDoc, index) {
              promises.push(encrypt.generateDocumentKey(32));
            });

            return Promise.all(promises);
          })
          .then(function(docKeys) {
            // temp save new docKeys for later use
            newDocumentKeys = docKeys;

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
            _.forEach(encryptedSharedDocuments, function(sharedDoc, index) {
              promises.push(encrypt.encryptDocumentKey(newDocumentKeys[index], owner.encryption.publicKey));
            });

            return Promise.all(promises);
          })
          .then(function(docKeysEnc) {
            // temp save new docKeysEnc
            newEncryptedDocumentKeys = docKeysEnc;

            promises = [];

            // parse through every encrypted shared document
            _.forEach(encryptedSharedDocuments, function(encryptedSharedDoc, index) {
              // decrypt every encrypted shared document
              promises.push(encryptedSharedDoc.decrypt(authentication));
            });

            // next step when decryption is finished for all shared documents
            return Promise.all(promises);
          })
          .then(function(decrSharedDocs) {
            promises = [];
            // parse through every decrypted shared document
            _.forEach(decrSharedDocs, function(decrSharedDoc, index) {
              // replace old authentication with a new one for each shared document
              newAuthentication.documentAccess[decrSharedDoc._id] = newDocumentKeys[index];
              // reset hasAccess to empty array
              decrSharedDoc.hasAccess = [];
              // overwrite the old encryptedDocumentKey with the newEncryptedDocumentKey 
              // only the user has access to the shared documents now
              decrSharedDoc.documentKey = newEncryptedDocumentKeys[index];
              // save all shared documents
              promises.push(decrSharedDoc.saveAsync({
                authentication: newAuthentication
              }));
            });

            // next step when saving is finished for all shared documents
            return Promise.all(promises);
          })
          .then(function(encrSharedDocs) {
            // check if session management is allowed
            _.forEach(encrSharedDocs, function(encrSharedDoc, index) {
              // if not remove the key from new session payload
              if (!encrSharedDoc.allowSession) {
                delete newAuthentication.documentAccess[encrSharedDoc._id];
              }
            });
            // resolve the new authentication so a new token with the changed payload can be signed
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