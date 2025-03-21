var Database = (typeof window !== "undefined")? window.Database : require('../database');

const rel_ = '#';  // '#'
const node_ = '_';  // '_'

Database.chain.unset = function(node){
	if( this && node && node[node_] && node[node_].put && node[node_].put[node_] && node[node_].put[node_][rel_] ){
		this.put( { [node[node_].put[node_][rel_]]:null} );
	}
	return this;
}
