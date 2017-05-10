 TIMEOUT(10000000000);
 log.log("first simulation message at time : " + time + "\n");
 //import Java Package to JavaScript
 //importPackage(java.io);
while (true) {
   log.log(time + ":" + id + ":" + msg + "\n");
   YIELD();
}
 // Use JavaScript object as an associative array
// outputs = new Object();

/* 
 while (true) {
 	//Has the output file been created.
 	if(! outputs[id.toString()]){
 		// Open log_<id>.txt for writing.
 		// BTW: FileWriter seems to be buffered.
 		outputs[id.toString()]= new java.io.FileWriter("log_" + id +".txt");
 	}
 	//Write to file.
 	outputs[id.toString()].write(time + " " + msg + "\n");
   
 	try{
 		//This is the tricky part. The Script is terminated using
 		// an exception. This needs to be caught.
 		YIELD();
 	} catch (e) {
 		//Close files.
 		for (var ids in outputs){
 			outputs[ids].close();
 		}
 		//Rethrow exception again, to end the script.
 		throw('test script killed');
 	}
 }
*/
