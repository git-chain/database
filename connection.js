;(function(){

  /* UNBUILD */
  function USE(arg, req){
    return req? require(arg) : arg.slice? USE[R(arg)] : function(mod, path){
      arg(mod = {exports: {}});
      USE[R(path)] = mod.exports;
    }
    function R(p){
      return p.split('/').slice(-1).toString().replace('.js','');
    }
  }
  if(typeof module !== "undefined"){ var MODULE = module }
  /* UNBUILD */

	;USE(function(module){
    if(typeof window !== "undefined"){ module.window = window }
    var tmp = module.window || module;
		var Connection = tmp.Connection || function(){};

    if(Connection.window = module.window){ Connection.window.Connection = Connection }
    try{ if(typeof MODULE !== "undefined"){ MODULE.exports = Connection } }catch(e){}
    module.exports = Connection;
	})(USE, './root');
  
	;USE(function(module){

		var Connection = USE('./root'), Database = (Connection.window||'').Database || USE('./database', 1);
		(Database.Connection = Connection).Database = Database;
    var ST = 0;

    if(!Database.window){ try{ USE('./lib/connection', 1) }catch(e){} }
		Database.on('opt', function(at){ start(at) ; this.to.next(at) }); // make sure to call the "next" middleware adapter.

		function start(root){
			if(root.connection){ return }
			var opt = root.opt, peers = opt.peers;
			if(false === opt.connection){ return }
			if((typeof process !== "undefined") && 'false' === ''+(process.env||'').Connection){ return }
			if(!Database.window){ return }
			var connection = root.connection = {}, tmp, id;
			var last = JSON.parse((localStorage||'')[(opt.file||'')+'connection/']||null) || {};
			Object.keys(last.peers||'').forEach(function(key){
				tmp = peers[id = key] = peers[id] || {};
				tmp.id = tmp.url = id;
			});
			tmp = peers[id = 'https://gun-rs.iris.to/gun'] = peers[id] || {};
			tmp.id = tmp.url = id;

			var mesh = opt.mesh = opt.mesh || Database.Mesh(root); // DAM!
			mesh.way = function(msg){
				if(root.$ === msg.$ || (msg._||'').via){
					mesh.say(msg, opt.peers);
					return;
				}
				var at = (msg.$||'')._;
				if(!at){ mesh.say(msg, opt.peers); return }
				if(msg.get){
					if(at.connection){ return } // don't ask for it again!
					at.connection = {};
				}
				mesh.say(msg, opt.peers);
			}
		}

		var empty = {}, yes = true, u;

		module.exports = Connection;
	})(USE, './connection');
}());
