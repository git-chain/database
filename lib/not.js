if(typeof window !== "undefined"){
  var Database = window.Database;
} else { 
  var Database = require('../database');
}

var u;

Database.chain.not = function(cb, opt, t){
	return this.get(ought, {not: cb});
}

function ought(at, ev){ ev.off();
	if(at.err || (u !== at.put)){ return }
	if(!this.not){ return }
	this.not.call(at.database, at.get, function(){ need.to.implement; });
}