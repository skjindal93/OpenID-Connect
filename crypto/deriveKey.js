var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');

exports.deriveKey = function(algorithm, baseKey, derivedKeyType, extractable, keyUsages){
	var deriveKeypromise = new Q.Promise(function(resolve,reject){
		if (!algorithm.hasOwnProperty("name")){
			reject ("Name of algorithm is not provided");
		}

		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (algorithms.deriveKeyalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}

		//TODO : To continue
	
	});
	return deriveKeypromise;
};