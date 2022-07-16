
    if(typeof window !== "undefined"){ module.window = window }

    var tmp = module.window || module, u;
    var Encryption = tmp.Encryption || {};

    if(Encryption.window = module.window){ Encryption.window.Encryption = Encryption }

    try{ if(u+'' !== typeof MODULE){ MODULE.exports = Encryption } }catch(e){}
    module.exports = Encryption;
  