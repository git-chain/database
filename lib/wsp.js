;(function(wsp){
	var Database = require('../database')
	, ws = require('ws').Server
	, http = require('./http')
	, url = require('url');
	Database.on('opt').event(function(database, opt){
		database.__.opt.ws = opt.ws = database.__.opt.ws || opt.ws || {};
		function start(server, port, app){
			if(app && app.use){ app.use(database.wsp.server) }
			server = database.__.opt.ws.server = database.__.opt.ws.server || opt.ws.server || server;
			require('./ws')(database.wsp.ws = database.wsp.ws || new ws(database.__.opt.ws), function(req, res){
				var ws = this;
				req.headers['sid'] = ws.sid = (ws.sid? ws.sid : req.headers['sid']);
				ws.sub = ws.sub || database.wsp.on('network').event(function(msg){
					if(!ws || !ws.send || !ws._socket || !ws._socket.writable){ return this.off() }
					if(!msg || (ws.sid && msg.headers && msg.headers['sid'] === ws.sid)){ return }
					if(msg && msg.headers){ delete msg.headers['ws-rid'] }
					try{ws.send(Database.text.ify(msg));
					}catch(e){} // juuuust in case.
				});
				database.wsp.wire(req, res);
			});
			database.__.opt.ws.port = database.__.opt.ws.port || opt.ws.port || port || 80;
		}
		var wsp = database.wsp = database.wsp || function(server, auth){
			database.wsp.auth = auth;
			if(!server){ return database }
			if(Database.fns.is(server.address)){
				if(server.address()){
					start(server, server.address().port);
					return database;
				}
			}
			if(Database.fns.is(server.get) && server.get('port')){
				start(server, server.get('port'));
				return database;
			}
			var listen = server.listen;
			server.listen = function(port){
				var serve = listen.apply(server, arguments);
				start(serve, port, server);
				return serve;
			}
			return database;
		}
		database.wsp.on = database.wsp.on || Database.on.create();
		database.wsp.regex = database.wsp.regex || opt.route || opt.path || /^\/gun/i;
		database.wsp.poll = database.wsp.poll || opt.poll || 1;
		database.wsp.pull = database.wsp.pull || opt.pull || database.wsp.poll * 1000;
		database.wsp.server = database.wsp.server || function(req, res, next){ // http
			next = next || function(){};
			if(!req || !res){ return next(), false }
			if(!req.url){ return next(), false }
			if(!req.method){ return next(), false }
			var msg = {};
			msg.url = url.parse(req.url, true);
			if(!database.wsp.regex.test(msg.url.pathname)){ return next(), false } // TODO: BUG! If the option isn't a regex then this will fail!
			if(msg.url.pathname.replace(database.wsp.regex,'').slice(0,3).toLowerCase() === '.js'){
				res.writeHead(200, {'Content-Type': 'text/javascript'});
				res.end(database.wsp.js = database.wsp.js || require('fs').readFileSync(__dirname + '/../database.js'));
				return true;
			}
			return http(req, res, function(req, res){
				if(!req){ return next() }
				var stream, cb = res = require('./jsonp')(req, res);
				if(req.headers && (stream = req.headers['sid'])){
					stream = (database.wsp.peers = database.wsp.peers || {})[stream] = database.wsp.peers[stream] || {sid: stream};
					stream.sub = stream.sub || database.wsp.on('network').event(function(req){
						if(!stream){ return this.off() } // self cleans up after itself!
						if(!req || (req.headers && req.headers['sid'] === stream.sid)){ return }
						(stream.queue = stream.queue || []).push(req);
						stream.drain(stream.reply);
					});
					cb = function(r){ (r.headers||{}).poll = database.wsp.poll; res(r) }
					stream.drain = stream.drain || function(res){
						if(!res || !stream || !stream.queue || !stream.queue.length){ return }
						res({headers: {'sid': stream.sid}, body: stream.queue });
						stream.off = setTimeout(function(){ stream = null }, database.wsp.pull);
						stream.reply = stream.queue = null;
						return true;
					}
					clearTimeout(stream.off);
					if(req.headers.pull){
						if(stream.drain(cb)){ return }
						return stream.reply = cb;
					}
				}
				database.wsp.wire(req, cb);
			}), true;
		}
		if((database.__.opt.maxSockets = opt.maxSockets || database.__.opt.maxSockets) !== false){
			require('https').globalAgent.maxSockets = require('http').globalAgent.maxSockets = database.__.opt.maxSockets || Infinity;
		}
		database.wsp.msg = database.wsp.msg || function(id){
			if(!id){
				return database.wsp.msg.debounce[id = Database.text.random(9)] = Database.time.is(), id;
			}
			clearTimeout(database.wsp.msg.clear);
			database.wsp.msg.clear = setTimeout(function(){
				var now = Database.time.is();
				Database.obj.map(database.wsp.msg.debounce, function(t,id){
					if((now - t) < (1000 * 60 * 5)){ return }
					Database.obj.del(database.wsp.msg.debounce, id);
				});
			},500);
			if(id = database.wsp.msg.debounce[id]){
				return database.wsp.msg.debounce[id] = Database.time.is(), id;
			}
		};
		database.wsp.msg.debounce = database.wsp.msg.debounce || {};
		database.wsp.wire = database.wsp.wire || (function(){
			// all streams, technically PATCH but implemented as PUT or POST, are forwarded to other trusted peers
			// except for the ones that are listed in the message as having already been sending to.
			// all states, implemented with GET, are replied to the source that asked for it.
			function flow(req, res){
				if (!req.auth || req.headers.broadcast) {
					database.wsp.on('network').emit(Database.obj.copy(req));
				}
				if(req.headers.rid){ return } // no need to process.
				if(Database.is.lex(req.body)){ return tran.get(req, res) }
				else { return tran.put(req, res) }
			}
			function tran(req, res){
				if(!req || !res || !req.body || !req.headers || !req.headers.id){ return }
				if(database.wsp.msg(req.headers.id)){ return }
				req.method = (req.body && !Database.is.lex(req.body))? 'put' : 'get';
				if(database.wsp.auth){ return database.wsp.auth(req, function(reply){
					if(!reply.headers){ reply.headers = {} }
					if(!reply.headers['Content-Type']){ reply.headers['Content-Type'] = tran.json }
					if(!reply.rid){ reply.headers.rid = req.headers.id }
					if(!reply.id){ reply.headers.id = database.wsp.msg() }
					res(reply);
				}, flow) }
				else { return flow(req, res) }
			}
			tran.get = function(req, cb){
				var key = req.url.key
				, reply = {headers: {'Content-Type': tran.json, rid: req.headers.id, id: database.wsp.msg()}};
				// NTS HACK! SHOULD BE ITS OWN ISOLATED MODULE! //
				if(req && req.url && req.url.pathname && req.url.pathname.indexOf('nts') >= 0){
					return cb({headers: reply.headers, body: {time: database.time.is() }});
				}
				// NTS END! SHOULD HAVE BEEN ITS OWN MODULE //
				// ALL HACK! SHOULD BE ITS OWN MODULE OR CORE? //
				if(req && req.url && database.obj.has(req.url.query, '*')){
					return database.all(req.url.key + req.url.search, function(err, list){
						cb({headers: reply.headers, body: (err? (err.err? err : {err: err || "Unknown error."}) : list || null ) })
					});
				}
				key = req.body;
				var opt = {key: false, local: true};
				(database.__.opt.wire.get||function(key, cb){cb(null,null)})(key, function(err, node){
					reply.headers.id = database.wsp.msg();
					if(err || !node){
						if(opt.on && opt.on.off){ opt.on.off() }
						return cb({headers: reply.headers, body: (err? (err.err? err : {err: err || "Unknown error."}) : null)});
					}
					if(Database.obj.empty(node)){
						if(opt.on && opt.on.off){ opt.on.off() }
						return cb({headers: reply.headers, body: node});
					} // we're out of stuff!
					cb({headers: reply.headers, chunk: node }); // Use this if you don't want streaming chunks feature.
				}, opt);
			}
			tran.put = function(req, cb){
				// This will give you much more fine-grain control over security, transactions, and what not.
				var reply = {headers: {'Content-Type': tran.json, rid: req.headers.id, id: database.wsp.msg()}};
				if(!req.body){ return cb({headers: reply.headers, body: {err: "No body"}}) }
				if(Database.is.graph(req.body)){
					if(req.err = Database.union(database, req.body, function(err, ctx){ // TODO: BUG? Probably should give me ctx.graph
						if(err){ return cb({headers: reply.headers, body: {err: err || "Union failed."}}) }
						var ctx = ctx || {}; ctx.graph = {};
						Database.is.graph(req.body, function(node, soul){
							ctx.graph[soul] = database.__.graph[soul];
						});
						(database.__.opt.wire.put || function(g,cb){cb("No save.")})(ctx.graph, function(err, ok){
							if(err){ return cb({headers: reply.headers, body: {err: err || "Failed."}}) } // TODO: err should already be an error object?
							cb({headers: reply.headers, body: {ok: ok || "Persisted."}});
						}, {local: true});
					}).err){ cb({headers: reply.headers, body: {err: req.err || "Union failed."}}) }
				} else {
					cb({headers: reply.headers, body: {err: "Not a valid graph!"}});
				}
			}
			database.wsp.on('network').event(function(req){
				// TODO: MARK! You should move the networking events to here, not in WSS only.
			});
			tran.json = 'application/json';
			return tran;
		}());
		if(opt.server){
			wsp(opt.server);
		}

		if(database.wsp.driver){ return }
		var driver = database.wsp.driver = {};
		var noop = function(){};
		var get = database.__.opt.wire.get || noop;
		var put = database.__.opt.wire.put || noop;
		var driver = {
			put: function(graph, cb, opt){
				put(graph, cb, opt);
				opt = opt || {};
				if(opt.local){ return }
				var id = database.wsp.msg();
				database.wsp.on('network').emit({ // sent to dynamic peers!
					headers: {'Content-Type': 'application/json', id: id},
					body: graph
				});
				var ropt = {headers:{}, WebSocket: WebSocket};
				ropt.headers.id = id;
				Database.obj.map(opt.peers || database.__.opt.peers, function(peer, url){
					Database.request(url, graph, function(err, reply){
						reply.body = reply.body || reply.chunk || reply.end || reply.write;
						if(err || !reply || (err = reply.body && reply.body.err)){
							return cb({err: Database.log(err || "Put failed.") });
						}
						cb(null, reply.body);
					}, ropt);
				});
			},
			get: function(lex, cb, opt){
				get(lex, cb, opt);
				opt = opt || {};
				if(opt.local){ return }
				if(!Database.request){ return console.log("Server could not find default network abstraction.") }
				var ropt = {headers:{}};
				ropt.headers.id = database.wsp.msg();
				Database.obj.map(opt.peers || database.__.opt.peers, function(peer, url){
					Database.request(url, lex, function(err, reply){
						reply.body = reply.body || reply.chunk || reply.end || reply.write;
						if(err || !reply || (err = reply.body && reply.body.err)){
							return cb({err: Database.log(err || "Get failed.") });
						}
						cb(null, reply.body);
					}, ropt);
				});
			}
		}
		var WebSocket = require('ws');
		Database.request.WebSocket = WebSocket;
		Database.request.createServer(database.wsp.wire);
		database.__.opt.wire = driver;
		database.opt({wire: driver}, true);
	});
}({}));
