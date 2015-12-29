exports.encryptionPlugin = require('./dist/encryptionPlugin');
exports.encryptionService = require('./dist/encryptionService')();
exports.resetAccessPermissions = require('./dist/encryptionWrapper')().resetAccessPermissions;