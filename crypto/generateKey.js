/*
	Promise<any> generateKey(AlgorithmIdentifier algorithm, boolean extractable, KeyUsage[] keyUsages);
*/
var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var nodecrypto = require('crypto');
var Q = require('q');


exports.generateKey = function(algorithm,extractable,keyUsages){
	
	var generateKeypromise = new Q.Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}

		var algo = algorithm.name;

		//Check if the algo name is in the suggested algorithms
		if (algorithms.generateKeyalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}
		
		if (!keyUsages){
			reject("KeyUsages are not provided");
		}

		if (typeof(keyUsages)!="object"){
			reject("KeyUsages should be an array");
		}
		//Checking if the any of the value of keyUsages are in the Recognized Key Usage Values

		if (!functions.checkRecognizedKeyUsageValues(keyUsages)){
			reject ("InvalidAccessError");
		}
		
		switch(algo){
			case "HMAC":
				var length;
				
				//If hash member is not present in algorithm, return SyntaxError
				//Point 2: Generate Key in HMAC
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}

				//Point 3: Generate Key HMAC
				if (!algorithm.hasOwnProperty("length")){
					reject("Length is not provided");
				}
				//Check whether !=0 or just >0
				else if (algorithm.length>0){
					length = algorithm.length;
				}
				else {
					reject("Data Error");
				}

				if (!algorithm.hash.name){
					reject("Name of hash algorithm not provided");
				}
				
				else if (algorithm.hash.name!="SHA-1" && algorithm.hash.name!="SHA-256"){
					reject("Not supported hash algorithm");
				}

				//Point 4: Generate Key HMAC
				if (keyUsages.indexOf("sign")==-1 && keyUsages.indexOf("verify")==-1){
					reject ("DataError");
				}
				
				//hashKeyAlgorithm: new Key Algorithm
				var hashKeyAlgorithm = {
					name : algorithm.hash.name,
				}

				//new HmacKeyAlgorithm, though there is no name attribute in HmacKeyAlgorithm 
				//still attribute name assigned as said in Point 9
				var HmacKeyAlgorithm = {	
					name : "HMAC",
					hash : hashKeyAlgorithm,	
				}

				//TODO : Generate some random key using the length attribute
				//var array = new Uint8Array(length/8);
				var array = nodecrypto.randomBytes(length/8).toString('hex');
				array = functions.convertPlainTextToArrayBufferView(functions.convertHexToString(array));
				var randomKey = array;

				var key = {
					//Since HMAC is a symmetric algorithm, so type : "secret"
					type : "secret",
					extractable : extractable,
					algorithm : HmacKeyAlgorithm,
					usages : keyUsages,
					data : randomKey
				};
				
				resolve(key);
				break;

			case "AES-CBC":

				var length;

				if (!algorithm.hasOwnProperty("name")){
					reject("SyntaxError");
				}

				
				if (!algorithm.hasOwnProperty("length")){
					reject("SyntaxError");
				}
				//Check whether !=0 or just >0

				else if (algorithm.length!=128 && algorithm.length!=192 && algorithm.length!=256){
					reject("Data Error");
					
				}
				else {
					length = algorithm.length;
				}

				if (keyUsages.indexOf("encrypt")==-1 && keyUsages.indexOf("decrypt")==-1 && keyUsages.indexOf("wrapKey")==-1 && keyUsages.indexOf("unwrapKey")==-1){
					reject ("DataError");
				}

				//new AeKeyAlgorithm, though there is no name attribute in AesKeyAlgorithm 
				//still attribute name assigned as said in Point 9
				var AesKeyAlgorithm = {	
					name : "AES-CBC",
					length : length
				}

				//TODO : Generate some random key using the length attribute
				//var array = new Uint8Array(length/8);
				var array = nodecrypto.randomBytes(length/8).toString('hex');
				array = functions.convertPlainTextToArrayBufferView(functions.convertHexToString(array));
				var randomKey = array;

				var key = {
					//Since HMAC is a symmetric algorithm, so type : "secret"
					type : "secret",
					extractable : extractable,
					algorithm : AesKeyAlgorithm,
					usages : keyUsages,
					data : randomKey
				};

				resolve(key);
				break;

			case "RSA-OAEP":
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("modulusLength")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("publicExponent")){
					reject("SyntaxError");
				}

				if (keyUsages.indexOf("encrypt")==-1 && keyUsages.indexOf("decrypt")==-1 && keyUsages.indexOf("wrapKey")==-1 && keyUsages.indexOf("unwrapKey")==-1){
					reject ("InvalidAccessError");
				}

				//TODO: Generate RSA key pair
				//DJCL must have a generate function in RSA
				var keyPair = {};

				var RsaHashedKeyAlgorithm = {
					name : "RSA-OAEP",
					modulusLength : algorithm.modulusLength,
					publicExponent : algorithm.publicExponent,
					hash : algorithm.hash,
				};

				keyPair.publicKey = {
					type : "public",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : true,
					//TODO : Get public Key data from rsa_generate
					//TODO : Intersection of keyUsages and ["encrypt","wrapKey"]
					usages : keyUsages
				};

				keyPair.privateKey = {
					type : "private",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : extractable,
					//TODO : Get private Key data from rsa_generate
					//TODO : Intersection of keyUsages and ["decrypt","unwrapKey"]
					usages : keyUsages,
				};

				resolve(keyPair);
				break;

			case "RSASSA-PKCS1-v1_5":
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("modulusLength")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("publicExponent")){
					reject("SyntaxError");
				}

				if (keyUsages.indexOf("sign")==-1 && keyUsages.indexOf("verify")==-1){
					reject ("DataError");
				}

				//TODO: Generate RSA key pair
				//DJCL must have a generate function in RSA
				var keyPair = {};

				var RsaHashedKeyAlgorithm = {
					name : "RSASSA-PKCS1-v1_5",
					modulusLength : algorithm.modulusLength,
					publicExponent : algorithm.publicExponent,
					hash : algorithm.hash
				};

				keyPair.publicKey = {
					type : "public",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : true,
					//TODO : Intersection of keyUsages and ["verify"]
					usages : keyUsages
				};

				keyPair.privateKey = {
					type : "private",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : extractable,
					//TODO : Intersection of keyUsages and ["sign"]
					usages : keyUsages,
				};

				resolve(keyPair);
				break;

		}
	});
	
	return generateKeypromise;
};