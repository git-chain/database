;(function(){
	var Database = (typeof window !== "undefined")? window.Database : require('../database');
	var ify = Database.node.ify, empty = {}, u;
	console.log("Index space is beta, API may change!");
	Database.chain.space = function(key, data, opt){
		if(data instanceof Function){
			return travel(key, data, opt, this);
		}
		var database = this;
		if(Database.is(data)){
			data.get(function(soul){
				if(!soul){
					return cb && cb({err: "Indexspace cannot link `undefined`!"});
				}
				database.space(key, Database.val.link.ify(soul), opt);
			}, true);
			return database;
		}
		var cb = (opt instanceof Function && opt), rank = (opt||empty).rank || opt, root = database.back(-1), tmp;
		database.get(function(soul){
			if(!soul){
				soul = (database.back('opt.uuid') || Database.text.random)(9);
			}
			var shell = {}, l = 0, tmp;
			var atom = Database.text.ify({get: key, put: data});
			tmp = {}; tmp[key] = data;
			shell.$ = ify(tmp, soul);
			tmp = {}; tmp[key.slice(0,l = 1)] = atom;
			shell[0] = ify(tmp, soul+'"');
			Database.list.map(index(1, key.length), function(i){
				tmp = {}; tmp[key.slice(l,i)] = atom;
				shell[i] = ify(tmp, soul+'"'+key.slice(0,l));
				l = i;
			});
			tmp = {}; tmp[key.slice(l, key.length)] = atom;
			shell[l+1] = ify(tmp, soul+'"'+key.slice(0,l));
			database.put(shell, cb, {soul: soul, shell: shell});
		},true);
		return database;
	}
	function travel(key, cb, opt, ref){
		var root = ref.back(-1), tmp;
		opt = opt || {};
		opt.ack = opt.ack || {};
		ref.get(function(soul){
			ref.get(key).get(function(msg, eve){
				eve.off();
				opt.exact = true;
				opt.ack.key = key;
				opt.ack.data = msg.put;
				if(opt.match){ cb(opt.ack, key, msg, eve) }
			});
			//if(u !== msg.put){
			//	cb(msg.put, msg.get, msg, eve);
			//	return;
			//}
			opt.soul = soul;
			opt.start = soul+'"';
			opt.key = key;
			opt.top = index(0, opt.find);
			opt.low = opt.top.reverse();
			find(opt, cb, root);
		}, true);
	}
	function find(o, cb, root){
		var id = o.start+o.key.slice(0,o.low[0]);
		root.get(id).get(function(msg, eve){
			eve.off();
			o.ack.tree = {};
			if(u === msg.put){
				if(!o.exact){ return o.match = true }
				cb(o.ack, id, msg, eve);
				return;
				o.low = o.low.slice(1);
				if(!o.low.length){
					cb(u, o.key, msg, eve);
					return;
				}
				find(o, cb, root);
				return;
			}
			Database.node.is(msg.put, function(v,k){
				if(!(k = Database.obj.ify(v) || empty).get){ return }
				o.ack.tree[k.get] = k.put;
			});
			if(!o.exact){ return o.match = true }
			cb(o.ack, id, msg, eve);
		});
	}
	function index(n, m, l, k){
		l = l || [];
		if(!m){ return l }
	  k = Math.ceil((n||1) / 10);
	  if((n+k) >= m){ return l }
	  l.push(n + k);
	  return index(n + k, m, l);
	}
}());
