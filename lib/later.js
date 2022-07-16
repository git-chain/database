var Database = Database || require('../database');
Database.chain.open || require('./open');

Database.chain.later = function(cb, age){
	var database = this;
	age = age * 1000; // convert to milliseconds.
	setTimeout(function(){
		database.open(cb, {off: true});
	}, age);
	return database;
}
