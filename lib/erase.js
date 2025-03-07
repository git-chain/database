var Database = (typeof window !== "undefined")? window.Database : require('../database');

Database.on('opt', function(root){
	this.to.next(root);
	if(root.once){ return }
	root.on('put', function(msg){
		Database.graph.is(msg.put, null, function(val, key, node, soul){
			if(null !== val){ return }
			// TODO: Refactor this to use `.off()`?
			var tmp = root.graph[soul];
			if(tmp){
				delete tmp[key];
			}
			tmp = tmp && tmp._ && tmp._['>'];
			if(tmp){
				delete tmp[key];
			}
			tmp = root.next;
			if(tmp && (tmp = tmp[soul]) && (tmp = tmp.put)){
				delete tmp[key];
				tmp = tmp._ && tmp._['>'];
				if(tmp){
					delete tmp[key];
				}
			}
		});
		this.to.next(msg);
	});
});
