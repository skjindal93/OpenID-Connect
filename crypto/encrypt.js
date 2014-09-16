/*
	Promise<any> encrypt(AlgorithmIdentifier algorithm, Key key, CryptoOperationData data);
*/
var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');

exports.encrypt = function(algorithm,key,data){
//TODO: Do we have to check key.algorithm.name = algorithm.name	
	var encryptpromise = new Q.Promise(function(resolve,reject){

		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}
		var algo = algorithm.name;
		
		//If algorithm for sign is not in the suggested algorithms list,reject with DOMException Error
		if (algorithms.encryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}
		
		

		if (!key.usages){
			reject("Key Usages not provided");
		}
		else if (key.usages.indexOf("encrypt")==-1){
			reject("InvalidAccessError");
		}

		switch(algo){
			case "AES-CBC":
				if (!algorithm.iv){
					reject("IV should be provided");
				}

				if (!algorithm.hasOwnProperty("iv")){
					reject("SyntaxError");
				}

				if (algorithm.iv.length != 16){
					reject("DataError");
				}

				var iv = functions.convertArrayBufferViewToPlainText(algorithm.iv);
				
				data = functions.convertArrayBufferViewToPlainText(data);

				var cipher;
				
				aes.setKey(functions.convertArrayBufferViewToPlainText(key.data));
				
				cipher = aes.CBC(data,iv,false);
				cipher = functions.convertPlainTextToArrayBufferView(cipher);
				resolve(cipher);
				
				break;
				
			case "RSA-OAEP":
				var label;
				if (!key.hasOwnProperty("type")){
					reject("Type of key is not provided");
				}
				else if (key.type!="public"){
					reject("InvalidAccessError");
				}

				if (!algorithm.hasOwnProperty("label")){
					label = "";
				}
				else {
					label = algorithm.label;
				}

				var cipher;
				data = functions.convertArrayBufferViewToPlainText(data);
				var publicKey = functions.convertArrayBufferViewToPlainText(key.publicKey.data);
				cipher = rsa.encrypt(data,publicKey);
				resolve(cipher);

				//TODO : Do something rsa.encrypt and some MGF
				//Points 4,5 and 6 of encrypt in RSA-OAEP
		}
	});
	return encryptpromise;	
};