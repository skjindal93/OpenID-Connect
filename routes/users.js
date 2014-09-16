var express = require('express');
var router = express.Router();
var querystring = require('querystring');
var url = require('url');
var functions = require('../crypto/functions');
var crypto = require('../crypto/subtlecrypto').crypto;

//All the clients that have registered with the authorization provider
var clients = {
	"client_id" : {
		secret : 'secret',
		redirect_uri : 'http://localhost:3000',
	},
};



//The issuer of the tokens
var issuer = "http://localhost:3000";

var algorithm = {name: 'AES-CBC', length : 256 };
var iv = "000102030405060708090a0b0c0d0e0f";
var encryptalgo = {name: 'AES-CBC', iv: functions.convertPlainTextToArrayBufferView(functions.convertHexToString(iv))};
var usages = ['encrypt','decrypt'];
var extractable = true;
var key = null;

/* GET users listing. */
router.get('/', function(req, res) {
	var urlcontent = url.parse(req.url, true).query;
	for(var key in urlcontent){
		urlcontent[key] = decodeURIComponent(urlcontent[key]);
	}
	//Checking if the required URL parameters are present.
	if (!urlcontent.scope || !urlcontent.response_type || !urlcontent.client_id || !urlcontent.redirect_uri || !urlcontent.state){
		console.log("error");
	}
	else {
		var scope = urlcontent.scope;
		scope = scope.split(' ');
		var response_type = urlcontent.response_type;
		var client_id = urlcontent.client_id;
		var client_secret = clients.client_id.secret;
		var redirect_uri = urlcontent.redirect_uri;
		//scope should have openid,response_type should be code and client id's redirect_uri should be redirect_uri sent in URL
		if (scope.indexOf("openid")==-1 || response_type!='code' || !clients.client_id || clients.client_id.redirect_uri!=redirect_uri){
			console.log("error");
		}
		else {
			var state = urlcontent.state;
			req.session.client_id = client_id;
			req.session.state = state;
			req.session.redirect_uri = redirect_uri;
			req.session.scope = scope;
			res.render('users');
			/*if (urlcontent.display){
				var display = urlcontent.display;
				switch(display){
					case 'page':
						res.render('users');
						break;
					case 'popup':
						res.render('users');
						break;
					case 'touch':
						break;
					case 'wap':
						break;
					default:
				}
			}
			else*/
		}
	}
});

router.post('/', function(req, res) {
	var formcontent = req.body;
	var name = formcontent["user"];
	var password = formcontent["password"];
	//Authenticating User
	if (name=="shubham" && password=="s"){
		//When authetication end point authenticates user, it gets the sub value from it's database of users.
		var sub = "unique identifier for user";

		var code = req.session.client_id + "&" + req.session.scope + "&" + req.session.redirect_uri + "&" + sub;
		crypto.subtle.generateKey(algorithm, extractable, usages).then(function(result){
			key = result;
			//Save key in a database containing client id and client_secret
			return crypto.subtle.encrypt(encryptalgo,key,functions.convertPlainTextToArrayBufferView(code));
		}).then(function(result){
			code = new Buffer(functions.convertArrayBufferViewToPlainText(result));
			code = code.toString('base64');
		});

		var auth_response = {
			code : code,
			state : req.session.state,
		};
		
		var oauthresponse = querystring.stringify(auth_response);
		//res.redirect('/');
		console.log(oauthresponse);
		//Sending OAuthResponse to RP
		res.redirect('/?'+''+oauthresponse);
	}
	
});

module.exports = router;
