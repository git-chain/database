;(function(){
	var Database = (typeof window !== "undefined")? window.Database : require('../database');
	var ify = Database.node.ify, u;
	Database.chain.time = function(data, a, b){
		if(data instanceof Function){
			return travel(data, a, b, this);
		}
		var database = this, root = database.back(-1);
		var cb = (a instanceof Function && a) || (b instanceof Function && b);
		if(Database.is(data)){
			data.get(function(soul){
				if(!soul){
					return cb && cb({err: "Timegraph cannot link `undefined`!"});
				}
				database.time(Database.val.link.ify(soul), a, b);
			}, true);
			return database;
		}
		opt = (cb === a)? b : a;
		opt = Database.text.is(opt)? {key: opt} : opt || {};
		var t = new Date(Database.state()).toISOString().split(/[\-t\:\.z]/ig);
		var p, tmp = t.pop();
		database.get(function(soul){
			var id = soul;
			p = id;
			if(!p){ id = p = (database.back('opt.uuid') || Database.text.random)(9) }
			// could shrink this into a loop. Do later?
			t = [p].concat(t);
			var rid = opt.key || (database.back('opt.uuid') || Database.text.random)(9);
			var milli = ify({}, t.join(':'));
			milli[rid] = data;
			tmp = t.pop();
			var sec = ify({}, t.join(':'));
			sec[tmp] = milli;
			tmp = t.pop();
			var min = ify({}, t.join(':'));
			min[tmp] = sec;
			tmp = t.pop();
			var hour = ify({}, t.join(':'));
			hour[tmp] = min;
			tmp = t.pop();
			var day = ify({}, t.join(':'));
			day[tmp] = hour;
			tmp = t.pop();
			var month = ify({}, t.join(':'));
			month[tmp] = day;
			tmp = t.pop();
			var year = ify({}, t.join(':'));
			year[tmp] = month;
			tmp = t.pop();
			var time = ify({}, t.join(':') || id);
			time[tmp] = year;
			database.put(time, cb);
		}, true);
		return database;
	}
	function travel(cb, opt, b, database){
		var root = database.back(-1), tmp;
		(opt = Database.num.is(opt)? {last: opt} : opt || {}).seen = opt.seen || {};
		var t = now(opt.start);
		database.on(function(data, key, msg, eve){
			var at = msg.$._, id = at.link || at.soul || Database.node.soul(data);
			if(!id){ return }
			if(false === opt.next){ eve.off() }
			else { opt.next = true }
			opt.start = [opt.id = id].concat(t);
			opt.low = opt.low || opt.start;
			opt.top = opt.top || opt.start;
			opt.now = [id].concat(now());
			//console.log("UPDATE");
			find(opt, cb, root, opt.at? opt.now : opt.at = opt.start);
		});
		return database;
	}
	function now(t){
		return new Date(t || Database.state()).toISOString().split(/[\-t\:\.z]/ig).slice(0,-1);
	}
	function find(o, cb, root, at, off){
		var at = at || o.at, t = at.join(':'), tmp;
		if(!off){
			if(o.seen[t]){ return }
			o.seen[t] = true;
		}
		var next = (o.low || o.start)[at.length];
		root.get(t).get(function(msg, ev){
			if(off){ ev.off() }
			var g = this;
			//console.log(at, msg.put);
			if(u === msg.put){
				find(o, cb, root, at.slice(0,-1), off);
				return;
			}
			if(7 < at.length){
				var l = Object.keys(msg.put).length;
				if(l === o.seen[t]){ return }
				var when = +(toDate(at));
				Database.node.is(msg.put, function(v, k){
					cb(v, k, when, ev);
					if(o.last){ --o.last }
				});
				o.seen[t] = l;
				if(!o.last){ return }
				if(o.last <= 0){ return }
				o.low = at;
				var tmp = at.slice(0,-1);
				find(o, cb, root, tmp, true);
				return;
			}
			if(o.last && false !== off){
				var keys = Object.keys(msg.put).sort().reverse();
				var less = Database.list.map(keys, function(k){
					if(parseFloat(k) < parseFloat(next)){ return k }
				});
				if(!less){
					find(o, cb, root, at.slice(0,-1), true);
				} else {
					var tmp = (at || o.at).slice();
					tmp.push(less);
					(o.low = tmp.slice()).push(Infinity);
					find(o, cb, root, tmp, true);
				}
			}
			if(off){ return }
			if(!o.next){ return }
			if(at < o.start.slice(0, at.length)){ return }
			var n = [o.id].concat(now()), top = n[at.length];
			Database.node.is(msg.put, function(v, k){
				if(k > top){ return }
				(v = at.slice()).push(k);
				find(o, cb, root, v, false);
			});
		})
	}
	function toDate(at){
		at = at.slice(-7);
		return new Date(Date.UTC(at[0], parseFloat(at[1])-1, at[2], at[3], at[4], at[5], at[6]));
	}
}());