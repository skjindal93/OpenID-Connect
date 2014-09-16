//var exports.crypto = document.createElement('div');
//TODO Check all reject values and fill them with DOMException as mentioned in the W3C Web Crytpo API
//TODO Replace all hasOwnProperty with ! . Go through each of them manually

module.exports.crypto = {
	subtle : {
		encrypt : require("./encrypt").encrypt,
		decrypt : require("./decrypt").decrypt,
		sign : require("./sign").sign,
		verify : require("./verify").verify,
		digest : require("./digest").digest,
		generateKey : require("./generateKey").generateKey,
		deriveKey : require("./deriveKey").deriveKey,
		importKey : require("./importKey").importKey,
		exportKey : require("./exportKey").exportKey,
		wrapKey : require("./wrapKey").wrapKey,
		unwrapKey : require("./unwrapKey").unwrapKey,
	},
};
