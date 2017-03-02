TIMEOUT(3000000000);

/* conf */
//ADDRESS_ROUTER = "aaaa::212:7401:1:101";
//ADDRESS_SERVER = "aaaa::212:7402:2:202";
ADDRESS_ROUTER = "aaaa:0000:0000:0000:c30c:0000:0000:0001"
ADDRESS_SERVER = "aaaa:0000:0000:0000:c30c:0000:0000:0002"
NR_PINGS = 10;
CMD_PING_PREFIX = "ping6 -c " + NR_PINGS + " -I tun0 ";
CMD_TUNNEL = "make connect-router-cooja";
CMD_WGET_ROUTER = "wget -t 1 -T 10 -O - http:\/\/[" + ADDRESS_ROUTER + "]";
CMD_WGET_SERVER = "wget -t 1 -T 10 -O - http:\/\/[" + ADDRESS_SERVER + "]";
COAP_SAMPLECLIENT_JAR = "/home/user/Californium/ExampleClient.jar";

/* delay */
msg = "";
GENERATE_MSG(5000, "continue");
WAIT_UNTIL(msg.equals("continue"));

/* override simulation speed limit to realtime */
sim.setSpeedLimit(1.0);

/* create tunnel interface */
log.log("create tunnel interface\n");
//launcher = new java.lang.ProcessBuilder["(java.lang.String[])"](['/bin/bash','-c',CMD_TUNNEL]);
launcher = new java.lang.ProcessBuilder("/bin/bash","-c",CMD_TUNNEL);
//launcher.directory(new java.io.File("../../examples/er-rest-example"));
launcher.directory(new java.io.File("/home/martin/workspace/contiki-oscoap/examples/er-rest-example"));
launcher.redirectErrorStream(true);
tunProcess = launcher.start();
tunRunnable = new Object();
tunRunnable.run = function() {
  var stdIn = new java.io.BufferedReader(new java.io.InputStreamReader(tunProcess.getInputStream()));
  while ((line = stdIn.readLine()) != null) {
    if (line != null && !line.trim().equals("")) {
      log.log("TUN> " + line + "\n");
    }
  }
  tunProcess.destroy();
}
new java.lang.Thread(new java.lang.Runnable(tunRunnable)).start();


msg = "";
GENERATE_MSG(100000000000000, "continue");
WAIT_UNTIL(msg.equals("continue"));

log.log("\n\nTest finished. Summary:\n");
log.log(testSummary + "\n");

tunProcess.destroy();
if (testFailed) {
  log.testFailed();
} else {
  log.testOK();
}
msg = "";
GENERATE_MSG(100000000000000, "continue");
WAIT_UNTIL(msg.equals("continue"));
