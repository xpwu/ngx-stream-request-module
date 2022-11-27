
let stm = require("stm/client.js");
let es6Client = require("stm/client.es6").Client;

App({
  onLaunch: function() {
      this.client = new stm.Client();
    this.client.setConnectArgs("ws://127.0.0.1:8001", function(){
        console.log("connect success");
      }
      , function(str){
        console.error(str);
      });
    this.client.onPush = function(data) {
      console.log(new stm.Client.StringView(data).toString());
    };

    this.es6Client = new es6Client();
    this.es6Client.setConnectArgs("ws://127.0.0.1:8001")
      .then(()=>console.log("es6 connect success"))
      .catch((error)=>{
        console.error(error);
      })
  },

  /**
   * @type stm.Client
   */
  client: null,

  es6Client: null
  
})