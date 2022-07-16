var Database = (typeof window !== "undefined")? window.Database : require('../database');

Database.chain.open || require('./open');

var _on = Database.chain.on;
Database.chain.on = function(a,b,c){
	if('value' === a){
		return this.open(b,c);
	}
	return _on.call(this, a,b,c);
}

Database.chain.bye || require('./bye');
Database.chain.onDisconnect = Database.chain.bye;
Database.chain.connected = function(cb){
	var root = this.back(-1), last;
	root.on('hi', function(peer){
		if(!cb){ return }
		cb(last = true, peer);
	});
	root.on('bye', function(peer){
		if(!cb || last === peer){ return }
		cb(false, last = peer);
	});
	return this;
}
