var Database = (typeof window !== "undefined")? window.Database : require('../database');
Database.chain.open || require('./open');

Database.chain.load = function(cb, opt, at){
	(opt = opt || {}).off = !0;
	return this.open(cb, opt, at);
}