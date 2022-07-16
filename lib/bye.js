var Database = (typeof window !== "undefined")? window.Database : require('../database');

Database.on('create', function(root){
	this.to.next(root);
	var mesh = root.opt.mesh;
	if(!mesh){ return }
	mesh.hear['bye'] = function(msg, peer){
		(peer.byes = peer.byes || []).push(msg.bye);
	}
	root.on('bye', function(peer){
		this.to.next(peer);
		if(!peer.byes){ return }
		var database = root.$;
		Database.obj.map(peer.byes, function(data){
			Database.obj.map(data, function(put, soul){
				database.get(soul).put(put);
			});
		});
		peer.byes = [];
	});
});

Database.chain.bye = function(){
	var database = this, bye = database.chain(), root = database.back(-1), put = bye.put;
	bye.put = function(data){
		database.back(function(at){
			if(!at.get){ return }
			var tmp = data;
			(data = {})[at.get] = tmp;
		});
		root.on('out', {bye: data});
		return database;
	}
	return bye;
}
