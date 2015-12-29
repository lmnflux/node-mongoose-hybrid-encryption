'use strict';

/**
 * @name encryptionPlugin
 *
 * @author Markus Engel <m.engel188@gmail.com>
 * @version 1.0.0
 *
 * @description
 * mongoose model extension, adds user specific encryption
 * @param {object} the schema to add this plugin to
 * @param {object} optional configuration or empty {}: 
 *  {array} excludeFromEncryption - specify all fields that should not be encrypted
 *  {array} additionalAuthenticatedFields - array of fields that should be added to the authentication
 *
 */
(function() {

  var _fp = require('lodash-fp');
  var semver = require('semver');
  var mongoose = require('mongoose');
  var ObjectId = mongoose.Schema.Types.ObjectId;

  var encryptionWrapper = require('./encryptionWrapper')();

  module.exports = function(schema, options) {

    var excludedFields, encryptedFields, authenticatedFields;
    // specifies default fields that must always be authenticated
    // these fields should never be changed
    var basicAuthenticatedFields = ['_id', '_ct', 'hasAccess', 'documentKey', 'signingKey'];

    /**
     * @name activate
     * @description processes the schema for usage
     * this function is executed once on sever start
     */
    function activate() {
      // we require a node version greater than 4.0.0 so check for it
      if (semver.gt(process.version, '4.0.0')) {
        // check if mongoose version requirement is met
        if (semver.lt(mongoose.version, '4.2.4')) {
          throw new Error('Mongoose version 4.2.4 or greater is required for Node version 4.0.0 or greater');
        }
      } else { // throw unsupported version error
        throw new Error('Node verseion 4.0.0 or greater is required');
      }

      // check if convention for excluded fields option are met
      // only excluding of top level fields is supported at this time
      if (_fp.any(function(field) {
          return field.indexOf('.') !== -1;
        }, options.excludeFromEncryption)) {
        throw new Error('Excluding field names containing "." is currently not supported');
      }

      // _id, _ct, hasAccess, documentKey and signingKey are the default excluded fields
      // union them with the optional excluded fields provided by the user
      excludedFields = _fp.union(['_id', '_ct', 'hasAccess', 'documentKey', 'signingKey'], options.excludeFromEncryption);
      // parse the fields we need to encrypt from the schema
      encryptedFields = _fp.chain(schema.paths)
        .filter(function(pathDetails) { // exclude indexed fields
          return !pathDetails._index;
        })
        .pluck('path') // get path name
        .difference(excludedFields) // exclude excluded fields
        .map(function(path) { // get the top level field
          return path.split('.')[0];
        })
        .uniq() // fields have to be unique, keep only the first occurence
        .value();

      // check if additional fields should be authenticated
      // if yes, union basic and the optional authenticated fields
      if (options.additionalAuthenticatedFields) {
        authenticatedFields = _fp.union(options.additionalAuthenticatedFields, basicAuthenticatedFields);
      } else { // else use only basic authenticated fields
        authenticatedFields = basicAuthenticatedFields;
      }

      // check if the schema has a _ct field, if not add it
      if (!schema.paths._ct) { // ciphertext
        schema.add({
          _ct: {
            type: Buffer
          }
        });
      }

      // check if the schema has a _ac field, if not add it
      if (!schema.paths._ac) { // authenticationcipher
        schema.add({
          _ac: {
            type: Buffer
          }
        });
      }

      // check if the schema has a hasAccess field, if not add it
      if (!schema.paths.hasAccess) { // array of authorized users
        schema.add({
          hasAccess: {
            type: [ObjectId]
          }
        });
      }

      // check if the schema has a documentKey field, if not add it
      if (!schema.paths.documentKey) {
        schema.add({
          documentKey: {
            type: String
          }
        });
      }

      // check if the schema has a signingKey field, if not add it
      if (!schema.paths.signingKey) {
        schema.add({
          signingKey: {
            type: String
          }
        });
      }
    }
    activate();

    /**
     * @name encrypt
     * @description adds an encrypt function to the schema
     * @param {object} authentication, the decrypted document and signingkeys
     * @param {object} optional update key value object for fields that should be updated on save
     * @return {document || error} the encrypted document or error  
     */
    schema.methods.encrypt = function(authentication, update) {
      var doc = this;
      return encryptionWrapper.encryptDocument(doc, authentication.documentAccess[doc._id].documentKey, encryptedFields, update)
        .then(function(encryptedDoc) {
          doc = encryptedDoc;

          return encryptionWrapper.signDocument(doc, authentication.documentAccess[doc._id].signingKey, authenticatedFields);
        });
    };

    /**
     * @name decrypt
     * @description adds a decrypt function to the schema,
     * the document is verified before the encryption
     * @param {object} authentication, the decrypted document and signingkeys
     * @return {document || error} the decrypted document or error  
     */
    schema.methods.decrypt = function(authentication) {
      var doc = this;

      return encryptionWrapper.verifyDocument(doc, authentication.documentAccess[doc._id].signingKey)
        .then(function() {
          return encryptionWrapper.decryptDocument(doc, authentication.documentAccess[doc._id].documentKey);
        });
    };

    /**
     * @name schema.pre('save')
     * @description the document needs to be encrypted automatically pre save
     * @params {function} next, can be called to save the document when pre is finished
     * default mongoose param
     * @params {options} decrypted document and signingkey and an optional field update object
     * @return {document || error} the encrypted document or error  
     */
    schema.pre('save', function(next, options) {
      var doc = this;
      // when user saves a document call the encryption function
      doc.encrypt(options.authentication, options.update)
        .then(function(computedDoc) {
          // set doc to the new computed encrypted signed doc
          doc = computedDoc;
          // now save the document
          next();
        })
        .catch(function(err) {
          next(err);
        });
    });

    /**
     * @name share
     * @description adds a share function to the schema
     * this function adds acces to a given user on executing document
     * @param {Mongoose shema object} UserModel shema
     * @param {object} the decrypted document and signingkeys as well as the owner _id
     * @param {mongo objectId} shareToId the id of the user who will be granted persmission to access the shared document
     * @return {promise resolve} "success" or error 
     */
    schema.methods.share = function(UserModel, authentication, shareToId) {
      var doc = this;

      return encryptionWrapper.shareDocument(UserModel, authentication, shareToId, doc);
    };

    /**
     * @name revokeAccess
     * @description adds a revokeAccess function to the schema
     * this function removes access from a given user on executing document
     * @param {Mongoose shema object} UserModel shema
     * @param {object} the decrypted document and signingkeys as well as the owner _id
     * @param {mongo objectId} revokeFromId the id of the user whose permissions will be revoked
     * @return {promise resolve} "success" or error 
     */
    schema.methods.revokeAccess = function(UserModel, authentication, revokeFromId) {
      var doc = this;

      return encryptionWrapper.revokeAccess(UserModel, authentication, revokeFromId, doc);
    };

    /**
     * @name revokeAll
     * @description adds a revokeAll function to the schema
     * this function removes access of all users on executing document
     * @param {Mongoose shema object} UserModel shema
     * @param {object} the decrypted document and signingkeys as well as the owner _id
     * @return {object || error} a new token payload with updated doc/sigkey or error
     */
    schema.methods.revokeAll = function(UserModel, authentication) {
      var doc = this;

      return encryptionWrapper.revokeAll(UserModel, authentication, doc);
    };

    /**
     * @name schema.pre('update')
     * @description if a dev uses the update function throw an error
     * normal update is not supported with the encryption plugin use save with custom update param
     * @params {function} next, called with an error to cancel the process
     * default mongoose param
     * @return {error}
     */
    schema.pre('update', function(next) {
      next(new Error('update is not supported on encrypted schemas, use save with custom update param'));
    });

    /**
     * @name schema.pre('findOneAndUpdate')
     * @description if a dev uses the update function throw an error
     * normal findOneAndUpdate is not supported with the encryption plugin use save with custom update param
     * @params {function} next, called with an error to cancel the process
     * default mongoose param
     * @return {error}
     */
    schema.pre('findOneAndUpdate', function(next) {
      next(new Error('update is not supported on encrypted schemas, use save with custom update param'));
    });

    /**
     * @name schema.pre('findByIdAndUpdate')
     * @description if a dev uses the findByIdAndUpdate function throw an error
     * normal findByIdAndUpdate is not supported with the encryption plugin use save with custom update param
     * @params {function} next, called with an error to cancel the process
     * default mongoose param
     * @return {error}
     */
    schema.pre('findByIdAndUpdate', function(next) {
      next(new Error('update is not supported on encrypted schemas, use save with custom update param'));
    });
  };
})();