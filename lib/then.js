var Database = (typeof window !== "undefined")? window.Database : require('../database');

Database.chain.promise = function(cb) {
  var database = this, cb = cb || function(ctx) { return ctx };
  return (new Promise(function(res, rej) {
    database.once(function(data, key){
    	res({put: data, get: key, database: this});
    });
  })).then(cb); //calling callback with resolved data
};

Database.chain.then = function(cb) {
	var database = this;
  var p = (new Promise((res, rej)=>{
    database.once(function (data, key) {
      res(data, key); //call resolve when data is returned
    })
  }))
  return cb ? p.then(cb) : p;
};
