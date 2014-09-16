/*
	Promise<any> exportKey(KeyFormat format, Key key);
*/
var algorithms = require('./algorithms');
var functions = require('./functions');
var aes = require('./DJCL/src/aes').aes;
var encoding = require('./DJCL/src/encoding').encoding;
var hashing = require('./DJCL/src/hashing').hashing;
var rsa = require('./DJCL/src/rsa').rsa;
var Q = require('q');

exports.exportKey = function(format,key){

	var exportKeypromise = new Q.Promise(function(resolve,reject){
		if (!key){
			reject("Key should be provided");
		}
		
		if (!key.algorithm){
			reject('Key does not have an algorithm');
		}
		else if (!key.algorithm.name){
			reject('Algorithm name not provided');
		}
		
		if (!format){
			reject("format should not be null");
		}

		var algo = key.algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (algorithms.exportKeyalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}
		
		//Checking if the format is one of the recognized key format values
		if (!functions.checkRecognizedKeyFormatValues(format)){
			reject ("SyntaxError");
		}

		if (!key.hasOwnProperty("extractable")){
			reject("extractable attribute of key should be provided");
		}

		if (!key.extractable){
			reject("InvalidAccessError");
		}

		switch(algo){
			case "HMAC":
				var data;
				switch(format){
					case "raw":
						//TODO : Let data be the raw octets of the key represented by key. What are raw octets?
						if (!key.hasOwnProperty("data")){
							reject ("keyData is not provided to key");
						}

						data = key.data;
						break;
				}

				//TODO : Return a new ArrayBuffer containing data.				
				resolve(data);
				break;
			case "AES-CBC":
				var data;

				switch(format){
					case "raw":
						//TODO : Let data be the raw octets of the key represented by key. What are raw octets?
						if (!key.hasOwnProperty("data")){
							reject ("keyData is not provided to key");
						}

						data = key.data;
						break;
				}
				
				//TODO : Return a new ArrayBuffer containing data.				
				resolve(data);
				break;

			case "RSA-OAEP":
				var result;

				switch(format){
					case "spki":
						if (!key.hasOwnProperty("type")){
							reject ("Type of key not provided");
						}
						else if (key.type != "public"){
							reject("InvalidAccessError");
						}
						
						if (!key.algorithm.hash.hasOwnProperty(name)){
							reject("Name attribute of hash algorithm is missing");
						}
						
						var temp = key.algorithm.hash.name;
						
						var name;
						if (temp == "SHA-1"){
							name = "id-sha1";
						}
						else if (temp == "SHA-256"){
							name = "id-sha256";
						}
						else if (temp == "SHA-384"){
							name = "id-sha384";
						}
						else if (temp == "SHA-512"){
							name = "id-sha512";
						}
						var hashAlgo = {
							oid : name,
							params : null
						};

						var maskAlgorithm = {
							oid : "id-mgf1",
							params : null
						};

						var subjectPublicKeyAlgorithm = {
							oid : "id-RSAES-OAEP",
							params : {
								hashAlgorithm : hashAlgo,
								MaskGenAlgorithm : maskAlgorithm
							},
						};

						var subjectPublicKeyInfo = {
							algorithm : subjectPublicKeyAlgorithm,
							subjectPublicKey : key.data
						};

						result = subjectPublicKeyInfo;
						break;

					case "pkcs8":
						if (!key.hasOwnProperty("type")){
							reject ("Type of key not provided");
						}
						else if (key.type != "private"){
							reject("InvalidAccessError");
						}
				}
				break;
				
			case "RSASSA-PKCS1-v1_5":
				
				break;

		}
	});
	
	return exportKeypromise;	
};