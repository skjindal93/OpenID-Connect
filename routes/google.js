var express = require('express');
var router = express.Router();

router.get('/', function(req, res) {
	res.render('front');
});

router.post('/', function(req, res) {

});

module.exports = router;