
    var u;
    if(u+''== typeof btoa){
      if(u+'' == typeof Buffer){
        try{ global.Buffer = require("buffer", 1).Buffer }catch(e){ }
      }
      global.btoa = function(data){ return Buffer.from(data, "binary").toString("base64") };
      global.atob = function(data){ return Buffer.from(data, "base64").toString("binary") };
    }
  