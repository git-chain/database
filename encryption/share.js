
    var User = require('./user'), Encryption = User.Encryption, Database = User.Database, noop = function(){};
    User.prototype.pair = function(){
      var user = this, proxy; // undeprecated, hiding with proxies.
      try{ proxy = new Proxy({DANGER:'\u2620'}, {get: function(t,p,r){
        if(!user.is || !(user._||'').encryption){ return }
        return user._.encryption[p];
      }})}catch(e){}
      return proxy;
    }
    // If authenticated user wants to delete his/her account, let's support it!
    User.prototype.delete = async function(alias, pass, cb){
      var database = this, root = database.back(-1), user = database.back('user');
      try {
        user.auth(alias, pass, function(ack){
          var pub = (user.is||{}).pub;
          // Delete user data
          user.map().once(function(){ this.put(null) });
          // Wipe user data from memory
          user.leave();
          (cb || noop)({ok: 0});
        });
      } catch (e) {
      }
      return database;
    }
    User.prototype.alive = async function(){
      const dbRoot = this.back(-1)
      try {
        // All is good. Should we do something more with actual recalled data?
        await authRecall(dbRoot)
        return dbRoot._.user._
      } catch (e) {
        const err = 'No session!'
        Database.log(err)
        throw { err }
      }
    }
    User.prototype.trust = async function(user){
      if (Database.is(user)) {
        user.get('pub').get((ctx, ev) => {
          console.log(ctx, ev)
        })
      }
      user.get('trust').get(path).put(theirPubkey);

    }
    User.prototype.grant = function(to, cb){
      var database = this, user = database.back(-1).user(), pair = user._.encryption, path = '';
      database.back(function(at){ if(at.is){ return } path += (at.get||'') });
      (async function(){
      var enc, sec = await user.get('grant').get(pair.pub).get(path).then();
      sec = await Encryption.decrypt(sec, pair);
      if(!sec){
        sec = Encryption.random(16).toString();
        enc = await Encryption.encrypt(sec, pair);
        user.get('grant').get(pair.pub).get(path).put(enc);
      }
      var pub = to.get('pub').then();
      var epub = to.get('epub').then();
      pub = await pub; epub = await epub;
      var dh = await Encryption.secret(epub, pair);
      enc = await Encryption.encrypt(sec, dh);
      user.get('grant').get(pub).get(path).put(enc, cb);
      }());
      return database;
    }
    User.prototype.secret = function(data, cb){
      var database = this, user = database.back(-1).user(), pair = user.pair(), path = '';
      database.back(function(at){ if(at.is){ return } path += (at.get||'') });
      (async function(){
      var enc, sec = await user.get('trust').get(pair.pub).get(path).then();
      sec = await Encryption.decrypt(sec, pair);
      if(!sec){
        sec = Encryption.random(16).toString();
        enc = await Encryption.encrypt(sec, pair);
        user.get('trust').get(pair.pub).get(path).put(enc);
      }
      enc = await Encryption.encrypt(data, sec);
      database.put(enc, cb);
      }());
      return database;
    }

    module.exports = User
  