
    var Encryption = require('./encryption'), Database, u;
    if(Encryption.window){
      Database = Encryption.window.Database || {chain:{}};
    } else {
      Database = require((u+'' == typeof MODULE?'.':'')+'./database', 1);
    }
    Encryption.Database = Database;

    function User(root){ 
      this._ = {$: this};
    }
    User.prototype = (function(){ function F(){}; F.prototype = Database.chain; return new F() }()) // Object.create polyfill
    User.prototype.constructor = User;

    Database.chain.user = function(pub){
      var database = this, root = database.back(-1), user;
      if(pub){
        pub = Encryption.opt.pub((pub._||'')['#']) || pub;
        return root.get('~'+pub);
      }
      if(user = root.back('user')){ return user }
      var root = (root._), at = root, uuid = at.opt.uuid || lex;
      (at = (user = at.user = database.chain(new User))._).opt = {};
      at.opt.uuid = function(cb){
        var id = uuid(), pub = root.user;
        if(!pub || !(pub = pub.is) || !(pub = pub.pub)){ return id }
        id = '~' + pub + '/' + id;
        if(cb && cb.call){ cb(null, id) }
        return id;
      }
      return user;
    }
    function lex(){ return Database.state().toString(36).replace('.','') }
    Database.User = User;
    User.Database = Database;
    User.Encryption = Database.Encryption = Encryption;
    module.exports = User;
  