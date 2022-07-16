
var Database = require('./index');
Database.chain.set = function(item, cb, opt){
	var database = this, root = database.back(-1), soul, tmp;
	cb = cb || function(){};
	opt = opt || {}; opt.item = opt.item || item;
	if(soul = ((item||'')._||'')['#']){ (item = {})['#'] = soul } // check if node, make link.
	if('string' == typeof (tmp = Database.valid(item))){ return database.get(soul = tmp).put(item, cb, opt) } // check if link
	if(!Database.is(item)){
		if(Object.plain(item)){
			item = root.get(soul = database.back('opt.uuid')()).put(item);
		}
		return database.get(soul || root.back('opt.uuid')(7)).put(item, cb, opt);
	}
	database.put(function(go){
		item.get(function(soul, o, msg){ // TODO: BUG! We no longer have this option? & go error not handled?
			if(!soul){ return cb.call(database, {err: Database.log('Only a node can be linked. Not "' + msg.put + '"!')}) }
			(tmp = {})[soul] = {'#': soul}; go(tmp);
		},true);
	})
	return item;
}
	