var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');

exports.decrypt = function(algorithm,key,data){

	var decryptpromise = new Q.Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}
		var algo = algorithm.name;

		//If algorithm for sign is not in the suggested algorithms list,reject with DOMException Error
		if (algorithms.decryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}

		if (!key.usages){
			reject("Key Usages not provided");
		}
		else if (key.usages.indexOf("decrypt")==-1){
			reject("InvalidAccessError");
		}

		switch(algo){
			case "AES-CBC":

				if (!algorithm.hasOwnProperty("iv")){
					reject("SyntaxError");
				}
				
				if (!algorithm.iv){
					reject("IV shoud not be null");
				}

				if (algorithm.iv.length != 16){
					reject("DataError");
				}

				var iv = functions.convertArrayBufferViewToPlainText(algorithm.iv);
				
				data = functions.convertArrayBufferViewToPlainText(data);
				aes.setKey(functions.convertArrayBufferViewToPlainText(key.data));
				
				var plaintext;
				plaintext = aes.CBC(data,iv,true);
				plaintext = functions.convertPlainTextToArrayBufferView(plaintext);
				resolve(plaintext);
				break;

			case "RSA-OAEP":
				var label;
				if (!key.hasOwnProperty("type")){
					reject("Type of key is not provided");
				}
				else if (key.type!="private"){
					reject("InvalidAccessError");
				}

				if (!algorithm.hasOwnProperty("label")){
					label = "";
				}
				else {
					label = algorithm.label;
				}

				data = functions.convertArrayBufferViewToPlainText(data);
				
				var plaintext;
				var privateKey = functions.convertArrayBufferViewToPlainText(key.privateKey.data);
				plaintext = rsa.decrypt(functions.convertStringToHex(data),privateKey);
				resolve(plaintext);

				//TODO : Do something rsa.decrypt and some MGF
				//Points 4,5 and 6 of encrypt in RSA-OAEP
				
		}	
	});
	return decryptpromise;
};