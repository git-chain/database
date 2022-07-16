
    var User = require('./user'), Encryption = User.Encryption, Database = User.Database;
    User.prototype.recall = function(opt, cb){
      var database = this, root = database.back(-1), tmp;
      opt = opt || {};
      if(opt && opt.sessionStorage){
        if(Encryption.window){
          try{
            var sS = {};
            sS = window.sessionStorage; // TODO: FIX BUG putting on `.is`!
            if(sS){
              (root._).opt.remember = true;
              ((database.back('user')._).opt||opt).remember = true;
              if(sS.recall || sS.pair) root.user().auth(JSON.parse(sS.pair), cb); // pair is more reliable than alias/pass
            }
          }catch(e){}
        }
        return database;
      }
      /*
        TODO: copy mhelander's expiry code back in.
        Although, we should check with community,
        should expiry be core or a plugin?
      */
      return database;
    }
  