
    var u, Database = (''+u != typeof window)? (window.Database||{chain:{}}) : require((''+u === typeof MODULE?'.':'')+'./database', 1);
    Database.chain.then = function(cb, opt){
      var database = this, p = (new Promise(function(res, rej){
        database.once(res, opt);
      }));
      return cb? p.then(cb) : p;
    }
  