var Database = Database || require('../database');

Database.chain.list = function(cb, opt){
	opt = opt || {};
	cb = cb || function(){}; 
	var database = this.put({}); // insert assumes a graph node. So either create it or merge with the existing one.
	database.last = function(obj, cb){
		var last = database.path('last');
		if(!arguments.length){ return last }
		return database.path('last').put(null).put(obj).val(function(val){ // warning! these are not transactional! They could be.
			console.log("last is", val);
			last.path('next').put(this._.node, cb);
		});
	}
	database.first = function(obj, cb){
		var first = database.path('first');
		if(!arguments.length){ return first }
		return database.path('first').put(null).put(obj).val(function(){ // warning! these are not transactional! They could be.
			first.path('prev').put(this._.node, cb);
		});
	}
	return database;
};

(function(){ // list tests
	return;
	var Database = require('../index');
	var database = Database({file: 'data.json'});
	Database.log.verbose = true;

	var list = database.list();
	list.last({name: "Mark Nadal", type: "human", age: 23}).val(function(val){
		//console.log("oh yes?", val, '\n', this.__.graph);
	});
	list.last({name: "Timber Nadal", type: "cat", age: 3}).val(function(val){
		//console.log("oh yes?", val, '\n', this.__.graph);
	});
	list.list().last({name: "Hobbes", type: "kitten", age: 4}).val(function(val){
		//console.log("oh yes?", val, '\n', this.__.graph);
	});
	list.list().last({name: "Skid", type: "kitten", age: 2}).val(function(val){
		//console.log("oh yes?", val, '\n', this.__.graph);
	});
	setTimeout(function(){ list.val(function(val){
		console.log("the list!", list.__.graph);
		return;
		list.path('first').val(Database.log)
			.path('next').val(Database.log)
			.path('next').val(Database.log);
	})}, 1000);

	return; // why is the code below even needed??? proabably some random debug code
	database.list().map(function(val, id){
		console.log("each!", id, val);
	})

}());
