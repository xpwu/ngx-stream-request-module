
let stm = require("stm/client.js");

App({
  onLaunch: function() {
      this.client = new stm.Client();
    this.client.setConnectArgs("wss://www.xpwu.me:10004", function(){
        console.log("connect success");
      }
      , function(str){
        console.error("connect failed");
      });
  },

  /**
   * @type stm.Client
   */
  client: null
  
})