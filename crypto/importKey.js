/*
	Promise<any> importKey(KeyFormat format, CryptoOperationData keyData, AlgorithmIdentifier? algorithm, 
							boolean extractable, KeyUsage[] keyUsages );
*/
var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');


exports.importKey = function(format,keyData,algorithm,extractable,keyUsages){

	var importKeypromise = new Q.Promise(function(resolve,reject){

		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}

		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (algorithms.importKeyalgos.indexOf(algo)==-1){

			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}
			
		//Checking if the format is one of the recognized key format values
		if (!functions.checkRecognizedKeyFormatValues(format)){
			reject ("SyntaxError");
		}

		//Checking if the any of the value of keyUsages are in the Recognized Key Usage Values
		if (!functions.checkRecognizedKeyUsageValues(keyUsages)){
			reject ("InvalidAccessError");
		}

		switch(algo){
			case "HMAC":

				//If usages contains an entry which is not "sign" or "verify", then return an error named DataError.
				if (keyUsages.indexOf("sign")==-1 && keyUsages.indexOf("verify")==-1){
					reject ("DataError");
				}

				var name;
				
				//Checking format
				switch(format){
					case "raw":
						
						//Not sure what is octet string.
						//TODO: Converting the keyData into normal String by convertArrayBufferViewToPlainText
						
						
						/*if (keyData.length==0){
							reject ("DataError");
						}*/


						if (algorithm.hasOwnProperty("hash") && algorithm.hash.hasOwnProperty("name")){
							name = algorithm.hash.name;
						}
						else {
							reject("SyntaxError");
						}

						break;
				}
				var data = functions.convertArrayBufferViewToPlainText(keyData);
				//hash is the new KeyAlgorithm
				var hash = {
					name : name
				};
				var HmacKeyAlgorithm = {
					name : "HMAC",
					hash : hash
				};
				var key = {
					type : "secret",
					extractable : extractable,
					algorithm : HmacKeyAlgorithm,
					
					//TODO: intersection of keyUsages and recognizedKeyUsageValues
					usages : keyUsages, 
					data : keyData
				};
				console.log(key);
				resolve(key);
				break;

			case "AES-CBC":


				var length;
				if (keyUsages.indexOf("encrypt")==-1 && keyUsages.indexOf("decrypt")==-1 && keyUsages.indexOf("wrapKey")==-1 && keyUsages.indexOf("unwrapKey")==-1){
					reject ("DataError");
				}

				switch(format){
					case "raw":
						//Not sure what is octet string.
						//TODO: Converting the keyData into normal String by convertArrayBufferViewToPlainText
						
						var checklength = keyData.length*8;
						
						if (checklength!=128 && checklength!=192 && checklength!=256){
							reject ("DataError");
						}
						else {
							length = checklength;
						}
						break;
				}

				var data = functions.convertArrayBufferViewToPlainText(keyData);

				var AesKeyAlgorithm = {
					name : "AES-CBC",
					length : length
				};

				var key = {
					type : "secret",
					extractable : extractable,
					algorithm : AesKeyAlgorithm,
					//TODO: intersection of keyUsages and recognizedKeyUsageValues
					usages : keyUsages, 
					data : keyData
				};

				resolve(key);
				break;
			
			case "RSA-OAEP":
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}
				var hash;
				var type;

				if (!algorithm.hash.hasOwnProperty("name")){
					reject ("DataError");
				}

				else {
					hash = algorithm.hash.name;	
				}
			
				switch(format){
					case "spki":
						//TODO : What is all the stuff about parsing?
						if (!keyData.hasOwnProperty('n') || !keyData.hasOwnProperty('e')){
							reject("Public Key not valid");
						}

						type = "public";
						
						break;

					case "pkcs8":

						//TODO : What is all the stuff about parsing?

						type = "private";
						break;

					case "jwk":
						if (keyData.hasOwnProperty('d')){
							type = "private";
						}
						else {
							if (!keyData.hasOwnProperty('n') || !keyData.hasOwnProperty('e')){
								reject("Public Key not valid");
							}
							type = "public";
						}
						break;

					default:
						reject("NotSupportedError");
				}

				var keyAlgorithm = {
					name : hash
				};

				var RsaHashedKeyAlgorithm = {
					name : "RSA-OAEP",
					modulusLength : keyData.n,
					publicExponent : keyData.e,
					hash : keyAlgorithm
				};

				var key = {
					type : type,
					extractable : extractable,
					algorithm : RsaHashedKeyAlgorithm,
					usages : keyUsages,
					data : keyData
				};

				resolve(key);
				break;
			case "RSASSA-PKCS1-v1_5":

				break;

		}
	});

	return importKeypromise;
};