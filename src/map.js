
var Database = require('./index'), next = Database.chain.get.next;
Database.chain.get.next = function(database, lex){ var tmp;
	if(!Object.plain(lex)){ return (next||noop)(database, lex) }
	if(tmp = ((tmp = lex['#'])||'')['='] || tmp){ return database.get(tmp) }
	(tmp = database.chain()._).lex = lex; // LEX!
	database.on('in', function(eve){
		if(String.match(eve.get|| (eve.put||'')['.'], lex['.'] || lex['#'] || lex)){
			tmp.on('in', eve);
		}
		this.to.next(eve);
	});
	return tmp.$;
}
Database.chain.map = function(cb, opt, t){
	var database = this, cat = database._, lex, chain;
	if(Object.plain(cb)){ lex = cb['.']? cb : {'.': cb}; cb = u }
	if(!cb){
		if(chain = cat.each){ return chain }
		(cat.each = chain = database.chain())._.lex = lex || chain._.lex || cat.lex;
		chain._.nix = database.back('nix');
		database.on('in', map, chain._);
		return chain;
	}
	chain = database.chain();
	database.map().on(function(data, key, msg, eve){
		var next = (cb||noop).call(this, data, key, msg, eve);
		if(u === next){ return }
		if(data === next){ return chain._.on('in', msg) }
		if(Database.is(next)){ return chain._.on('in', next._) }
		var tmp = {}; Object.keys(msg.put).forEach(function(k){ tmp[k] = msg.put[k] }, tmp); tmp['='] = next; 
		chain._.on('in', {get: key, put: tmp});
	});
	return chain;
}
function map(msg){ this.to.next(msg);
	var cat = this.as, database = msg.$, at = database._, put = msg.put, tmp;
	if(!at.soul && !msg.$$){ return } // this line took hundreds of tries to figure out. It only works if core checks to filter out above chains during link tho. This says "only bother to map on a node" for this layer of the chain. If something is not a node, map should not work.
	if((tmp = cat.lex) && !String.match(msg.get|| (put||'')['.'], tmp['.'] || tmp['#'] || tmp)){ return }
	Database.on.link(msg, cat);
}
var noop = function(){}, event = {stun: noop, off: noop}, u;
	