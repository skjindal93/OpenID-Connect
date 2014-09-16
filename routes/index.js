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

var client_id = "client_id";
//var client_id = "226931993245-evec6ojs5rvmufpqm3gla2shca64pcfk.apps.googleusercontent.com";
var client_secret = "secret";
//var client_secret = "aeMhpHpIARJS_-zKbtuhaVrZ";
var redirect_uri = 'http://localhost:3000';
var issuer = "http://localhost:3000";
//var issuer = "accounts.google.com";
var authorization_end_point = "http://localhost:3000/users";
//var authorization_end_point = "https://accounts.google.com/o/oauth2/auth";
var token_end_point = "http://localhost:3000/tokenend";
//var token_end_point = "https://accounts.google.com/o/oauth2/token";
var userinfo_end_point = "https://www.googleapis.com/plus/v1/people/me/openIdConnect";
//"server" for using server flow and "implicit" for using implicit flow
var server_implicit = "server";

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

  if (server_implicit=="server" && urlcontent.code && urlcontent.state){
  	if (req.session.state != urlcontent.state){
  		console.log("error");
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
		'Content-Length': tokenrequest.length,
		'Authorization' : "Basic "+authentication,
	};
	
	request.post({
		headers: headers,
		url :     token_end_point,
		//body:    "grant_type=authorization_code&code="+urlcontent.code+"&redirect_uri="+redirect_uri+"&client_id="+client_id+"&client_secret="+client_secret+"",
		body : tokenrequest,
	}, function(error, response, body){
		var tok = JSON.parse(response.body);
		console.log(tok);
		
		
		var access_token = tok["access_token"];
		var id_token = tok["id_token"];

		//Google's Public Key
		var key = {
   			"kty": "RSA",
   			"alg": "RS256",
   			"use": "sig",
   			"kid": "f0298bf50e9c8dbc625cbd72740e381726cdc573",
   			"n": "AOJxhgVmv1EuXdh7dQ1VI7VTAgJsosELPnYvEJC9CwEXjISx/BABusjCubB4z8IpsIxeNjOsPhryaPIfy2/A2p2hoAKULvYa6ztHtSPnGmj86zOhMoz/SggO9W/ZXBPXpNS/6BO9zyFzqK/GUoN4Jr+a0oYuUB4SYCOfob57L0W3",
   			"e": "AQAB"
		};


		/*var idtoken = JWT.parse(id_token,key);
		console.log(idtoken);
		var valid = idtoken.valid;
		if (valid){
			var idtoken = JSON.parse(idtoken.claims);

			var iss = idtoken["iss"];
			var aud = idtoken["aud"];
			if (iss == issuer && aud == client_id){
				console.log("Yay!!");
				console.log(access_token);
				request.get({
					headers : {'Content-Type' : 'application/x-www-form-urlencoded','Authorization' : 'Bearer '+ access_token},
					url : userinfo_end_point,
				}, function(error,response,body){
					var info = JSON.parse(response.body);
					res.send(info);
				});
			}	
		}
		*/

		res.send("1. Generate access_token, refresh_token in tokenend.js file.\
			2. Sign ID Token with a suitable key in tokenend.js file\
			3. Verify ID Token with the key in index.js\
			4. And then uncomment the above code.");
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
