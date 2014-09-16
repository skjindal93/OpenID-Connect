var express = require('express');
var router = express.Router();
var querystring = require('querystring');
var url = require('url');

router.get('/', function(req, res) {
	res.render('googlesignin');
});

router.post('/', function(req, res) {
});

module.exports = router;
