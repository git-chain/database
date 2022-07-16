;(function(){
	var Database = (typeof window !== "undefined")? window.Database : require('../database');

	Database.on('opt', function(root){
		once(root);
		this.to.next(root);
	});

	function once(root){
		if(root.once){ return }
		var forget = root.opt.forget = root.opt.forget || {};
		root.on('put', function(msg){
			Database.graph.is(msg.put, function(node, soul){
				if(!Database.obj.has(forget, soul)){ return }
				delete msg.put[soul];
			});
			this.to.next(msg);
		});
	}

}());
