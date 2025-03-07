
if(typeof Database === 'undefined'){ return }

var noop = function(){}, store, u;
try{store = (Database.window||noop).localStorage}catch(e){}
if(!store){
	Database.log("No localStorage exists to persist data to");
	store = {setItem: function(k,v){this[k]=v}, removeItem: function(k){delete this[k]}, getItem: function(k){return this[k]}};
}

var parse = JSON.parseAsync || function(t,cb,r){ var u; try{ cb(u, JSON.parse(t,r)) }catch(e){ cb(e) } }
var json = JSON.stringifyAsync || function(v,cb,r,s){ var u; try{ cb(u, JSON.stringify(v,r,s)) }catch(e){ cb(e) } }

Database.on('create', function lg(root){
	this.to.next(root);
	var opt = root.opt, graph = root.graph, acks = [], disk, to, size, stop;
	if(false === opt.localStorage){ return }
	opt.prefix = opt.file || 'db/';
	try{ disk = lg[opt.prefix] = lg[opt.prefix] || JSON.parse(size = store.getItem(opt.prefix)) || {}; // TODO: Perf! This will block, should we care, since limited to 5MB anyways?
	}catch(e){ disk = lg[opt.prefix] = {}; }
	size = (size||'').length;

	root.on('get', function(msg){
		this.to.next(msg);
		var lex = msg.get, soul, data, tmp, u;
		if(!lex || !(soul = lex['#'])){ return }
		data = disk[soul] || u;
		if(data && (tmp = lex['.']) && !Object.plain(tmp)){ // pluck!
			data = Database.state.ify({}, tmp, Database.state.is(data, tmp), data[tmp], soul);
		}
		//if(data){ (tmp = {})[soul] = data } // back into a graph.
		//setTimeout(function(){
		Database.on.get.ack(msg, data); //root.on('in', {'@': msg['#'], put: tmp, lS:1});// || root.$});
		//}, Math.random() * 10); // FOR TESTING PURPOSES!
	});

	root.on('put', function(msg){
		this.to.next(msg); // remember to call next middleware adapter
		var put = msg.put, soul = put['#'], key = put['.'], id = msg['#'], ok = msg.ok||'', tmp; // pull data off wire envelope
		disk[soul] = Database.state.ify(disk[soul], key, put['>'], put[':'], soul); // merge into disk object
		if(stop && size > (4999880)){ root.on('in', {'@': id, err: "localStorage max"}); return; }
		//if(!msg['@']){ acks.push(id) } // then ack any non-ack write. // TODO: use batch id.
		if(!msg['@'] && (!msg._.via || Math.random() < (ok['@'] / ok['/']))){ acks.push(id) } // then ack any non-ack write. // TODO: use batch id.
		if(to){ return }
		to = setTimeout(flush, 9+(size / 333)); // 0.1MB = 0.3s, 5MB = 15s 
	});
	function flush(){
		if(!acks.length && ((setTimeout.turn||'').s||'').length){ setTimeout(flush,99); return; } // defer if "busy" && no saves.
		var err, ack = acks; clearTimeout(to); to = false; acks = [];
		json(disk, function(err, tmp){
			try{!err && store.setItem(opt.prefix, tmp);
			}catch(e){ err = stop = e || "localStorage failure" }
			if(err){
				root.on('localStorage:error', {err: err, get: opt.prefix, put: disk});
			}
			size = tmp.length;

			//if(!err && !Object.empty(opt.peers)){ return } // only ack if there are no peers. // Switch this to probabilistic mode
			setTimeout.each(ack, function(id){
				root.on('in', {'@': id, err: err, ok: 0}); // localStorage isn't reliable, so make its `ok` code be a low number.
			},0,99);
		})
	}

});
	