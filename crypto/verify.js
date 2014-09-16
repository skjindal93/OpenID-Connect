/*
Promise<any> verify(AlgorithmIdentifier algorithm, Key key, CryptoOperationData signature, CryptoOperationData data);
*/
var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');

exports.verify = function(algorithm,key,signature,data){
	var verifypromise = new Q.Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}

		var algo = algorithm.name;
		
		//If algorithm for sign is not in the suggested algorithms list,reject with DOMException Error
		if (algorithms.verifyalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}

		if (!key.hasOwnProperty("usages")){
			reject("usages is not provided in key");
		}
		else if(key.usages.indexOf("verify")==-1){
			reject ("InvalidAccessError");
		}
		
		switch (algo){
			case "HMAC":
				
				//normalize the algorithm : means just check if the specified algorithm has all the specified
				//attributes in it.
				
				var hashalgo = key.algorithm.hash.name;
				
				//Convert back the arrayBufferView into string
				//hashing.HMAC(key,msg) => key and data are both ASCII strings.
				//key.data will be CryptoOperationData i.e. ArrayBuffer
				//data will be CryptoOperationData i.e. ArrayBuffer

				data = functions.convertArrayBufferViewToPlainText(data);
				var keydata = functions.convertArrayBufferViewToPlainText(key.data);
				var result;
				
				switch (hashalgo){
					case "SHA-1":
						hashing.hmac_hash = hashing.sha1;
						result = hashing.HMAC(keydata,data);
						break;
					case "SHA-256":
						hashing.hmac_hash = hashing.sha256;
						result = hashing.HMAC(keydata,data);
						break;	
				}
				//result is in hex and signature in CryptoOperationData
				//Convert result to string and signature to string
				result = functions.convertHexToString(result);
				signature = functions.convertArrayBufferViewToPlainText(signature);
				console.log(result);
				console.log(signature);
				if (result == signature){
					resolve(true);
				}
				else {
					resolve(false);
				}
				break;

			case "RSASSA-PKCS1-v1_5":
				if (!key.hasOwnProperty("type")){
					reject ("Type of key is not provided");
				}
				else if (key.type != "public"){
					reject("InvalidAccessError");
				}
				else {
					data = functions.convertArrayBufferViewToPlainText(data);
					//var privateKey = functions.convertArrayBufferViewToPlainText(key.data);
					
					
					var publicKey;
					publicKey = functions.convertArrayBufferViewToPlainText(key.publicKey.data);
					signature = functions.convertStringToHex(functions.convertArrayBufferViewToPlainText(signature));
					var result = rsa.verify_pkcs1_v1_5(data,signature,publicKey);
					resolve(result);	
				}
		}
	});
	return verifypromise;	
};