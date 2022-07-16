;(function(){
	var Database = (typeof window !== "undefined")? window.Database : require('../database');
	Database.state.node = function(node, vertex, opt){
		opt = opt || {};
		opt.state = opt.state || Database.state();
		var now = Database.obj.copy(vertex);
		Database.node.is(node, function(val, key){
			var ham = Database.HAM(opt.state, Database.state.is(node, key), Database.state.is(vertex, key), val, vertex[key]);
			if(!ham.incoming){
				// if(ham.defer){}
				return;
			}
			now = Database.state.to(node, key, now);
		});
		return now;
	}
}());
