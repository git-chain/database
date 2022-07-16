// This was written by the wonderful Forrest Tait
// modified by Mark to be part of core for convenience
// twas not designed for production use
// only simple local development.

var Database = require('../database'),
fs = require('fs');

Database.on('create', function(root){
	this.to.next(root);
	var opt = root.opt;
	if(true !== opt.localStorage){ return }
	if(false === opt.localStorage){ return }
	//if(process.env.RAD_ENV){ return }
	//if(process.env.AWS_S3_BUCKET){ return }
	opt.file = String(opt.file || 'data.json');
	var graph = root.graph, acks = {}, count = 0, to;
	var disk = Database.obj.ify((fs.existsSync || require('path').existsSync)(opt.file)? 
		fs.readFileSync(opt.file).toString()
	: null) || {};

	root.on('put', function(at){
		this.to.next(at);
		Database.graph.is(at.put, null, map);
		if(!at['@']){ acks[at['#']] = true; } // only ack non-acks.
		count += 1;
		if(count >= (opt.batch || 10000)){
			return flush();
		}
		if(to){ return }
		to = setTimeout(flush, opt.wait || 1);
	});

	root.on('get', function(at){
		this.to.next(at);
		var lex = at.get, soul, data, opt, u;
		//setTimeout(function(){
		if(!lex || !(soul = lex['#'])){ return }
		//if(0 >= at.cap){ return }
		if(Database.obj.is(soul)){ return match(at) }
		var field = lex['.'];
		data = disk[soul] || u;
		if(data && field){
			data = Database.state.to(data, field);
		}
		root.on('in', {'@': at['#'], put: Database.graph.node(data)});
		//},11);
	});

	var map = function(val, key, node, soul){
		disk[soul] = Database.state.to(node, key, disk[soul]);
	}

	var wait, u;
	var flush = function(){
		if(wait){ return }
		clearTimeout(to);
		to = false;
		var ack = acks;
		acks = {};
		fs.writeFile(opt.file, JSON.stringify(disk), function(err, ok){
			wait = false;
			var tmp = count;
			count = 0;
			Database.obj.map(ack, function(yes, id){
				root.on('in', {
					'@': id,
					err: err,
					ok: err? u : 1
				});
			});
			if(1 < tmp){ flush() }
		});
	}

	function match(at){
		var rgx = at.get['#'], has = at.get['.'];
		Database.obj.map(disk, function(node, soul, put){
			if(!Database.text.match(soul, rgx)){ return }
			if(has){ node = Database.state.to(node, has) }
			(put = {})[soul] = node;
			root.on('in', {put: put, '@': at['#']});
		});
	}
});
