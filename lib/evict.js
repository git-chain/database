;(function(){
	var Database = (typeof window !== "undefined")? window.Database : require('../database');
	var ev = {}, empty = {}, u;
	Database.on('opt', function(root){
		this.to.next(root);
		if(root.once){ return }
		if(typeof process == 'undefined'){ return }
		var util = process.memoryUsage, heap;
		if(!util){ return }
		try{ heap = require('v8').getHeapStatistics }catch(e){}
		if(!heap){ return }

		ev.max = parseFloat(root.opt.memory || (heap().heap_size_limit / 1024 / 1024) || process.env.WEB_MEMORY || 1399) * 0.8;
		
		setInterval(check, 1000);
		function check(){
			var used = util().rss / 1024 / 1024;
			var hused = heap().used_heap_size / 1024 / 1024;
			var tmp; if(tmp = console.STAT){ tmp.memax = parseFloat(ev.max.toFixed(1)); tmp.memused = parseFloat(used.toFixed(1)); tmp.memhused = parseFloat(hused.toFixed(1)); }
			if(hused < ev.max && used < ev.max){ return }
			//if(used < ev.max){ return }
			console.STAT && console.STAT('evict memory:', hused.toFixed(), used.toFixed(), ev.max.toFixed());
			GC();//setTimeout(GC, 1);
		}
		function GC(){
			var S = +new Date;
			var souls = Object.keys(root.graph||empty);
			var toss = Math.ceil(souls.length * 0.01);
			setTimeout.each(souls, function(soul){
				if(--toss < 0){ return 1 }
				root.$.get(soul).off();
			},0,99);
			root.dup.drop(1000 * 9); // clean up message tracker
			console.STAT && console.STAT(S, +new Date - S, 'evict');
		}
	});
}());