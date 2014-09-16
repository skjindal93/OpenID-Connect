var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');

exports.unwrapKey = function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages){
	var unwrapKeypromise = new Q.Promise(function(resolve,reject){
		var algorithm = unwrapAlgorithm;
		
		if (!algorithm.hasOwnProperty("name")){
			reject ("Name of algorithm is not provided");
		}

		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (algorithms.unwrapKeyalgos.indexOf(algo)==-1 && decryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}

		if (!unwrappedKeyAlgorithm.hasOwnProperty("name")){
			reject ("Name of the unwrap key algorithm is not provided");
		}

		if (alogrithms.importKeyalgos.indexOf(unwrappedKeyAlgorithm.name)==-1){
			reject("NotSupportedError");
		}

		if (!unwrappingKey.hasOwnProperty("usages")){
			reject ("usages attribute of unwrappingKey is not provided");
		}
		else if (unwrappingKey.usages.indexOf("unwrapKey")==-1){
			reject ("InvalidAccessError");
		}
		//Checking if the format is one of the recognized key format values
		if (!functions.checkRecognizedKeyFormatValues(format)){
			reject ("SyntaxError");
		}

		if (!functions.checkRecognizedKeyUsageValues(keyUsages)){
			reject("SyntaxError");
		}

		//TODO : How to unwrap the key
	});
	return unwrapKeypromise;
};