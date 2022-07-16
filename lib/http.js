var Database = require('../database')
,	formidable = require('formidable')
,	url = require('url');
module.exports = function(req, res, next){
	next = next || function(){}; // if not next, and we don't handle it, we should res.end
	if(!req || !res){ return next() }
	if(!req.url){ return next() }
	if(!req.method){ return next() }
	var msg = {};
	msg.url = url.parse(req.url, true);
	msg.method = (req.method||'').toLowerCase();
	msg.headers = req.headers;
	var u, body
	,	form = new formidable.IncomingForm()
	,	post = function(err, body){
		if(u !== body){ msg.body = body }
		next(msg, function(reply){
			if(!res){ return }
			if(!reply){ return res.end() }
			if(Database.obj.has(reply, 'statusCode') || Database.obj.has(reply, 'status')){
				res.statusCode = reply.statusCode || reply.status;
			}
			if(reply.headers){
				if(!(res.headersSent || res.headerSent || res._headerSent || res._headersSent)){
					Database.obj.map(reply.headers, function(val, field){
						if(val !== 0 && !val){ return }
						res.setHeader(field, val);
					});
				}
			}
			if(Database.obj.has(reply,'chunk') || Database.obj.has(reply,'write')){
				res.write(Database.text.ify(reply.chunk || reply.write) || '');
			}
			if(Database.obj.has(reply,'body') || Database.obj.has(reply,'end')){
				res.end(Database.text.ify(reply.body || reply.end) || '');
			}
		});
	}
	form.on('field',function(k,v){
		(body = body || {})[k] = v;
	}).on('file',function(k,v){
		return;
	}).on('error',function(e){
		if(form.done){ return }
		post(e);
	}).on('end', function(){
		if(form.done){ return }
		post(null, body);
	});
	form.parse(req);
}