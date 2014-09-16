var jq = document.createElement('script');
jq.src = "http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js";
document.getElementsByTagName('head')[0].appendChild(jq);

function getAlgos(column){
	var i=0;
	var array=[];
	var algos = ["RSAES-PKCS1-v1_5","RSASSA-PKCS1-v1_5","RSA-PSS","RSA-OAEP","ECDSA","ECDH","AES-CTR","AES-CBC","AES-CMAC","AES-GCM","AES-CFB","AES-KW","HMAC","DH","SHA-1","SHA-256","SHA-384","SHA-512","CONCAT","HKDF-CTR","PBKDF2"];
	$("#algorithms-index tbody tr td:nth-child("+column+")").each(function(){
		var str = this.innerHTML;
		if (str.length>0) {
			array.push(i);
			}
		i++;
	});

	var a = [];
	for (var i=0;i<array.length;i++){
		a.push(algos[array[i]]);
	}
	console.log(a);
}
	