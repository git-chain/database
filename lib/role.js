;(function(){

	function resolve(chain){
		Database.debug=1;
		//return;
		chain = chain || database.get('a').get('b').map().map().get('c').get('d').get(function(a,b,c,tmp){
			a.ID = a.ID || Database.text.random(2);
			console.log('********', a.put || a);
			//b.rid(a);
		});
		console.log("~~~~~~~~~~~~~~");
		window.chain = chain;
	}
	/*
		sync put: 5 node - 1 stop
		sync reload: 1 link 2 node - X stop
		sync resolve: 6 node - 0 stop : 3 node - 0 stop
		async put: 5 node + 3 node - 1 stop
		async reload: 2 link 1 node - X stop (2 links per each stop)
		async resolve: 6 node - 0 stop : 3 node - 0 stop

		sync put: 1 mum
		sync reload: 1 mum
		sync resolve: 1 mum
		async put: 1 mum
		async reload: 0 mum: 2 link 1 node
		async resolve: 1 mum

	*/

	function off(chain){
		chain = chain || database.get('users').map().get(function(a,b,c,tmp){
			console.log("***", a.put);
			b.rid(a);
		});
		database.get('users').get('alice').get(function(a,b){
			console.log(">>>", a.put);
		});
		console.log("vvvvvvvvvvvvv");
		window.chain = chain;
	}


	function soul(chain){
		Database.debug = 1;
		database.get('x').get('y').get('z').get('q').get(function(a,b,c){
			console.log("***", a.put || a);//,b,c);
		});
		setTimeout(function(){
			console.debug.j=1;
			console.debug.i=1;console.log("------------");
			database.get('x').get('y').put({
				z: {
					q: {r: {hello: 'world'}}
				}
			});
		},20);
		console.log("..............");
		window.chain = chain;
	}

	window.resolve = resolve;
	window.off = off;
	window.soul = soul;
	//localStorage.clear();sessionStorage.clear();
	setTimeout(function(){ resolve() },1);
	
	/*
		At the end of the day, you trust an entity, not data.
		That entity might be a person, or a group of people,
		it doesn't really matter - you do not trust a machine.

		Trust gives write access (public).
		Grant gives read access (private).

	*/

  function Role(){}
  if(typeof window !== "undefined"){ Role.window = window }
	var Database = (Role.window||{}).Database || require('../database');
	Database.SEA || require('../sea');
	if(!Database.User){ throw "No User System!" }
	var User = Database.User;

	User.prototype.trust = function(user){

	}

}());