exports.encryptionPlugin = require('./dist/encryptionPlugin');
exports.encryptionService = require('./dist/encryptionService')();
exports.resetAll = require('./dist/encryptionWrapper')().resetAll;