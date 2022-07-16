var Database = (typeof window !== "undefined")? window.Database : require('../database');

Database.chain.path = function(field, opt){
	var back = this, database = back, tmp;
	if(typeof field === 'string'){
		tmp = field.split(opt || '.');
		if(1 === tmp.length){
			database = back.get(field);
			return database;
		}
		field = tmp;
	}
	if(field instanceof Array){
		if(field.length > 1){
			database = back;
			var i = 0, l = field.length;
			for(i; i < l; i++){
				database = database.get(field[i]);
			}
		} else {
			database = back.get(field[0]);
		}
		return database;
	}
	if(!field && 0 != field){
		return back;
	}
	database = back.get(''+field);
	return database;
}