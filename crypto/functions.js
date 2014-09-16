var encoding = require('./DJCL/src/encoding').encoding;
var algorithms = require('./algorithms');

module.exports = {
	convertPlainTextToArrayBufferView : function convertPlainTextToArrayBufferView(str) {
		var buf = new ArrayBuffer(str.length);
		var abv = new Uint8Array(buf);
		for (var i=0; i<str.length; ++i) {
			abv[i] = encoding.charCode(str[i]);
		}
		return abv;
	},

	//TODO : See how to use encoding.fromCharCode here.
	convertArrayBufferViewToPlainText : function convertArrayBufferViewToPlainText(abv) {
		var str="";
		for (var i=0;i<abv.length;i++){
			str+=encoding.fromCharCode(abv[i]);
		}
		return str;
		//return String.fromCharCode.apply(null, new Uint8Array(abv));
	},

	convertHexToString : function convertHexToString(hex){
		return encoding.hstr2astr(hex);
	},

	convertStringToHex : function convertStringToHex(string){
		return encoding.astr2hstr(string);
	},

	checkRecognizedKeyUsageValues : function checkRecognizedKeyUsageValues(keyUsages){
		var ans = false;
		for (var i=0; i<algorithms.recognizedKeyUsageValues.length; i++){
			if (keyUsages.indexOf(algorithms.recognizedKeyUsageValues[i])==-1){
				ans = ans || false;
			}
			else {
				ans = true;
				return ans;
			}
		}
		return ans;
	},

	checkRecognizedKeyFormatValues : function checkRecognizedKeyFormatValues(format){
		var ans = false;
		for (var i=0; i<algorithms.recognizedKeyFormatValues.length; i++){
			if (algorithms.recognizedKeyFormatValues.indexOf(format)==-1){
				ans = ans || false;
			}
			else {
				ans = true;
				return ans;
			}
		}
		return ans;
	},
};

