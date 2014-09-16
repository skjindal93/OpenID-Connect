
/*typedef DOMString KeyType;

typedef DOMString KeyUsage;

interface Key {
  readonly attribute KeyType type;
  readonly attribute boolean extractable;
  readonly attribute KeyAlgorithm algorithm;
  readonly attribute KeyUsage[] usages;
};
*/

//Implements Key Interface
var key = function(){
	var type;
	var extractable;
	var algorithm;
	var usages;
	var data;
};