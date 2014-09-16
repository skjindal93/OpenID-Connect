var express = require('express');
var router = express.Router();
var querystring = require('querystring');
var url = require('url');
var http = require('http');
var JWT = require('../crypto/DJCL/src/jose').JWT;
var JWE = require('../crypto/DJCL/src/jose').JWE;

var client_id = "client_id";
var client_secret = "secret";
var redirect_uri = 'http://localhost:3000';

var code = client_id + redirect_uri;

router.get('/', function(req, res) {
	res.render('tokenend');
});

router.post('/', function(req, res) {
	var header=req.headers['authorization']||'',        // get the header
		token=header.split(/\s+/).pop()||'',            // and the encoded auth token
		auth=new Buffer(token, 'base64').toString(),    // convert from base64
		parts=auth.split(/:/),                          // split on colon
		username=parts[0],
		password=parts[1];


	if (username==client_id && password==client_secret){
		if (!req.body.grant_type || !req.body.code || !req.body.redirect_uri){
			console.log("error");
		}
		else {

			var grant_type = req.body.grant_type;
			var code_rp = req.body.code;
			var redirect_uri_rp = req.body.redirect_uri;
			//decrypt code_rp using the key stored in the database and split about & and check if all the parameters are valid
			if (grant_type=="authorization_code" /*&& code_rp == code*/ && redirect_uri_rp == redirect_uri){
				console.log("Hello");
				var header = {"typ":"JWT","alg":"HS256"};
				var firstpart = new Buffer(JSON.stringify(header)).toString("base64");
				var time = new Date();
				time = time.getTime();
				time = time/1000;
				var iat = time;
				var exp = time + 300;
				var id_token = {
					//should use https scheme only
					iss : 'localhost:3000/tokenend',
					sub : 'unique identifier for user',
					aud : username,
					exp : exp,
					iat : iat,
				};

				var secondpart = new Buffer(JSON.stringify(id_token)).toString("base64");
				var firstsecond = firstpart + "." + secondpart;
				var key = "shubham";

				var thirdpart = JWT.algfun[0].sign(firstsecond,key);
				var idtoken = firstsecond + "." + thirdpart;
				var token_response = {
					"access_token" : "access_token",
					"token_type" : "Bearer",
					"refresh_token" : "refresh_token",
					"expires_in" : 3600,
					"id_token" : idtoken,
				};
				
				res.writeHead(200, {"Content-Type": "application/json","Cache-Control" : "no-store","Pragma" : "no-cache"});
				res.end(JSON.stringify(token_response));
			}
			else {
				console.log("error");
			}
		}
		
	}
});

module.exports = router;