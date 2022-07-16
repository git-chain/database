var Database = (typeof window !== "undefined")? window.Database : require('../database');

Database.chain.promOnce = async function (limit, opt) {
 var database = this, cat = database._;
 if(!limit){limit = 100}
 if(cat.subs){
  var array = [];
  database.map().once((data, key)=>{
    var database = this;
    array.push(new Promise((res, rej)=>{
      res({ref: database, data:data, key:key});
    })
   )
 }, opt);
  await sleep(limit);
  return Promise.all(array)
} else {
  return (new Promise((res, rej)=>{
    database.once(function (data, key) {
      var database = this;
      res({ref:database,data:data,key:key});
      }, opt);
    }))
  }
 var chain = database.chain();
 return chain;
}

function sleep (limit) {
 return (new Promise((res, rej)=>{
   setTimeout(res, limit);
 }))
}

Database.chain.promPut = async function (item, opt) {
  var database = this;
  return (new Promise((res, rej)=>{
    database.put(item, function(ack) {
        if(ack.err){console.log(ack.err); ack.ok=-1; res({ref:database, ack:ack})}
        res({ref:database, ack:ack});
    }, opt);
  }))
}


Database.chain.promSet = async function(item, opt){
	var database = this, soul;
  var cb = cb || function(){};
	opt = opt || {}; opt.item = opt.item || item;
  return (new Promise(async function (res,rej) {
    if(soul = Database.node.soul(item)){ item = Database.obj.put({}, soul, Database.val.link.ify(soul)) }
		if(!Database.is(item)){
			if(Database.obj.is(item)){;
				item = await database.back(-1).get(soul = soul || Database.node.soul(item) || database.back('opt.uuid')()).promPut(item);
        item = item.ref;
			}
			res(database.get(soul || (Database.state.lex() + Database.text.random(7))).promPut(item));
		}
		item.get(function(soul, o, msg){
      var ack = {};
			if(!soul){ rej({ack:{err: Database.log('Only a node can be linked! Not "' + msg.put + '"!')}} ) }
			database.put(Database.obj.put({}, soul, Database.val.link.ify(soul)), cb, opt);
		},true);
		res({ref:item, ack:{ok:0}});
  }))
}

/*
* Function promOn
* @param callback (function) - function to be called upon changes to data
* @param option (object) - {change: true} only allow changes to trigger the callback
* @return - data and key
* subscribes callback to data
*/

Database.chain.promOn = async function (callback, option) {
  var database = this;
  return (new Promise((res, rej)=>{
    database.on(function (data, key){
      callback(data, key);
      res(data, key);
    }, option);
  }));
}
