var express = require('express');
var router = express.Router();
var querystring = require('querystring');
var request = require('request');
var url = require('url');
var http = require('http');
var functions = require('../crypto/functions');
var crypto = require('../crypto/subtlecrypto').crypto;
var JWT = require('../crypto/DJCL/src/jose').JWT;
var JWE = require('../crypto/DJCL/src/jose').JWE;


var client_id = "226931993245-pjncq3kpejc07bci0341rlganmk2tqt5.apps.googleusercontent.com";
var client_secret = "KToUuTbbp9vpVsemmnJASVU3";

var redirect_uri = 'http://localhost:3000/google-implicit';
var issuer = "accounts.google.com";
var authorization_end_point = "https://accounts.google.com/o/oauth2/auth";
var token_end_point = "https://accounts.google.com/o/oauth2/token";
var userinfo_end_point = "https://www.googleapis.com/plus/v1/people/me/openIdConnect";
//"server" for using server flow and "implicit" for using implicit flow
var server_implicit = "implicit";

var algorithm = {name: 'HMAC', hash :{ name:'SHA-256' }, length : 256 };
var signalgo = {name : 'HMAC'};
var usages = ['sign','verify'];
var extractable = true;
var key = null;
var state;

crypto.subtle.generateKey(algorithm, extractable, usages).then(function(result){
	key = result;
	return crypto.subtle.sign(signalgo,key,functions.convertPlainTextToArrayBufferView(client_id));
}).then(function(result){
	state = new Buffer(functions.convertArrayBufferViewToPlainText(result));
	state = state.toString('base64');
});


/* GET home page. */
router.get('/', function(req, res) {
  var urlcontent = url.parse(req.url, true).query;
  if (!req.session.state){
  	req.session.state = state;
  }

  if (!urlcontent.code || !urlcontent.state){
  	res.render('index', {state : req.session.state, client_id : client_id , redirect_uri : redirect_uri, authorization_end_point : authorization_end_point, server_implicit : server_implicit, userinfo_end_point : userinfo_end_point});	
  }

  if (server_implicit=="server" && urlcontent.code && urlcontent.state && !urlcontent.localresult){
  	if (req.session.state != urlcontent.state){
  		console.log("error");
  	}
  	res.render('state',{state:req.session.state,code:urlcontent.code});
  }
  else if (server_implicit=="server" && urlcontent.code && urlcontent.state && urlcontent.localresult){
  	if (req.session.state != urlcontent.state || urlcontent.localresult!="true"){
  		console.log("error");
  	}
  	if (!req.session.code){
  		req.session.code = querystring.stringify(urlcontent);
	}


  	var token_request = {
  		grant_type : "authorization_code",
  		code : urlcontent.code,
  		redirect_uri : redirect_uri
  	};

  	var tokenrequest = querystring.stringify(token_request);
  	//console.log(tokenrequest);
  	//var tokenrequest = token_request;
  	var authentication = new Buffer(client_id+":"+client_secret);
  	var authentication = authentication.toString('base64');

	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
	};

	if (!req.session.tokenrequest){
  		req.session.tokenrequest = tokenrequest;
	}

	request.post({
		headers: headers,
		url :     token_end_point,
		body:    "grant_type=authorization_code&code="+urlcontent.code+"&redirect_uri="+redirect_uri+"&client_id="+client_id+"&client_secret="+client_secret+"",
	}, function(error, response, body){

		if (!req.session.response){
  			req.session.response = JSON.stringify(response.body);
		}
	
		var tok = JSON.parse(response.body);
		console.log(tok);
		var access_token = tok["access_token"];
		var id_token = tok["id_token"];
		var keys;
		var valid = true;

		request.get({
			url : 'https://www.googleapis.com/oauth2/v2/certs',
		}, function(error,response,body){
			keys = JSON.parse(response.body);
			keys = keys["keys"];
			var idtoken = JWT.parse(id_token,keys[0]);
			if (!idtoken.valid){
				idtoken = JWT.parse(id_token,keys[1]);
				if (!idtoken.valid){
					valid = false;
				}
			}
			
			if (!req.session.idtoken){
  				req.session.idtoken = JSON.stringify(idtoken);
			}
	
			//Google's Public Key
			/*var key = {
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "9c70d320a8ea4293517698499d1baf5f21212b0a",
				"n": "AJ1i+ArZPApC3lp/fOdihTzZHTKE1x3bEj2xz9C+MnJbIBmWWOIAFFvu02J2qcS0chlMa/RCvWwCauylii1Rl0Hj7PLb8TsgKXmHqIVIOxK8IfpFUjKmj+5zsn09FDsnaABf5DwkSiiO0OXu5VRUWKtGwUjpJv9n4gGJfcFBa8Y9",
				"e": "AQAB"
			};*/
			
			console.log(idtoken);
			if (valid){
				var idtoken = JSON.parse(idtoken.claims);

				var iss = idtoken["iss"];
				var aud = idtoken["aud"];
				if (iss == issuer && aud == client_id){
					console.log("Yay!!");
					console.log(access_token);
					var header = {'Content-Type' : 'application/x-www-form-urlencoded','Authorization' : 'Bearer '+ access_token};
					if (!req.session.userinfo){
						req.session.userinfo = JSON.stringify(header);
					}
					request.get({
						headers : header,
						url : userinfo_end_point,
					}, function(error,response,body){
						var info = JSON.parse(response.body);
						//res.send(info);
						res.render('google', {info : JSON.stringify(info), userinfo : req.session.userinfo, code : req.session.code,tokenrequest : req.session.tokenrequest, response : req.session.response, idtoken : req.session.idtoken});	
					});
				}	
			}
		});

			
		
	});

  	/*var req = http.request(options, function(response){
		response.setEncoding('utf8');
		var str = '';
		response.on('data', function (chunk) {
			str += chunk;
		});

		response.on('end', function () {
			console.log(str);
			//Check the ID Token as in Section 3.1.3.7
			//Check the Access Token as in Section 3.1.3.5
			//res.send(str);
		});
	});
	req.on('error', function(e) {
 		console.log('problem with request: ' + e.message);
	});
	req.write(tokenrequest);
	req.end();*/
	
  }
});

router.post('/', function(req, res) {
	var formcontent = req.body;
	if (formcontent.hasOwnProperty("oauth-request")){
		var oauthrequest = querystring.stringify(auth_request);
		var options = {
			host: 'localhost',
			port: 3000,
			path: '/users',
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Content-Length': oauthrequest.length
			}
		};

		/*var req = http.request(options, function(response){
			response.setEncoding('utf8');
			var str = ''
			response.on('data', function (chunk) {
				str += chunk;
			});

			response.on('end', function () {
				//console.log(str);
				res.send(str);
			});
		});
		req.write(oauthrequest);
		req.end();*/
		res.redirect('/users?'+oauthrequest);
	}
});

module.exports = router;
