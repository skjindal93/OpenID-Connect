var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');

exports.wrapKey = function(format, key, wrappingKey, wrapAlgorithm){
	var wrapKeypromise = new Q.Promise(function(resolve,reject){
		var algorithm = wrapAlgorithm;
		
		if (!algorithm.hasOwnProperty("name")){
			reject ("Name of algorithm is not provided");
		}

		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (algorithms.wrapKeyalgos.indexOf(algo)==-1 && algorithms.encryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}
		//Checking if the format is one of the recognized key format values
		if (!functions.checkRecognizedKeyFormatValues(format)){
			reject ("SyntaxError");
		}

		if (!wrappingKey.hasOwnProperty("usages")){
			reject("usages attribute of wrapping key not specified");
		}
		else if (wrappingKey.usages.indexOf("wrapKey")==-1){
			reject("InvalidAccessError");
		}

		if (!key.hasOwnProperty("algorithm")){
			reject ("algorithm in key is not provided");
		}
		else if (!key.algorithm.hasOwnProperty("name")){
			reject("name of key algorithm not provided");
		}
		else if (algorithms.exportKeyalgos.indexOf(key.algorithm.name)==-1){
			reject("NotSupportedError");
		}

		if (!key.hasOwnProperty("extractable")){
			reject ("extractable attribute of key not specified");
		}
		else if (!key.extractable){
			reject("InvalidAccessError");
		}

		//TODO : How to wrap the key
	});
	return wrapKeypromise;
};