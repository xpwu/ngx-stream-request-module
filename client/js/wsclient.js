/**
 * Created by xpwu on 16/10/12.
 */

(function(ns){
  "use strict";

  /**
   *
   * @param {WSClient}content
   */
  function sendAllRequest(content) {
    for (var req in content.requests) {
      content.send(content.requests[req].reqid, content.requests[req].req);
    }
  }

  var reqIDstart = 200;
  var immID = reqIDstart-1;
  var pushID = 1; // need equal server

  var protocol = {
    /**
     *
     * @param {WSClient}content
     * @param {int}reqid
     * @param {string|ArrayBuffer}data
     */
    send: function(content, reqid, data){console.error("protocol not implement send");}
    /**
     *
     * @param {WSClient}content
     */
    , onOpen: function(content){console.error("protocol not implement onOpen");}
    /**
     *
     * @param {WSClient}content
     * @param {{data: ArrayBuffer}}message
     * @returns {null|{id:int, status:int, data:DataView}}
     */
    , onMessage: function(content, message){console.error("protocol not implement onMessage");}
    , extend: function(child) {
      if (child.__proto__) {
        child.__proto__ = this;
      } else {
        for (var propertyName in this) {
          if (this.hasOwnProperty(propertyName)
            && !child.hasOwnProperty(propertyName)) {
            child[propertyName] = this[propertyName];
          }
        }

        // IE won't copy toString using the loop above
        if (this.hasOwnProperty('toString')
          && !child.hasOwnProperty('toString')) {
          child.toString = this.toString;
        }
      }
      child.$parent = this;

      return child;
    }
  };

  /**
   *  message default protocol:
   *  request ---
   *    reqid | data
   *      reqid: 4 bytes, net order;
   *
   *  response ---
   *    reqid | status | data
   *      reqid: 4 bytes, net order;
   *      status: 1 byte, 0---success, 1---failed
   *      data: if status==success, data=<app data>
   *            if status==failed, data=<error reason>
   */
  var defaultProto = protocol.extend({
    /**
     *
     * @param {string|number}reqid
     * @param {string}data
     * @returns {ArrayBuffer}
     */
    buildFailedResponse: function(reqid, data) {
      data = new StringView(data);
      var buffer = new ArrayBuffer(4+1+data.rawData.byteLength);
      var dataView = new DataView(buffer);
      dataView.setUint32(0, reqid);
      dataView.setUint8(4, 1);
      var uint8 = new Uint8Array(buffer);
      uint8.set(data.rawData, 5);

      return {data:buffer};
    }
    /**
     *
     * @param {WSClient}content
     * @param {int}reqid
     * @param {string|ArrayBuffer}data
     */
    , send: function(content, reqid, data) {
      if (typeof data !== "string" || !data instanceof ArrayBuffer) {
        setTimeout(function () {
          onMessageDefault(content, buildFailedResponseDefault(reqid
            , "data type is error, must be string or ArrayBuffer"))
        }, 0);
        return;
      }

      data = new StringView(data);
      var buffer = new ArrayBuffer(4 + data.rawData.byteLength);
      (new DataView(buffer)).setUint32(0, reqid);
      (new Uint8Array(buffer)).set(data.rawData, 4);

      var uint8 = new Uint8Array(buffer);

      content.ws.send(buffer);
    }
    /**
     *
     * @param {WSClient}content
     */
    , onOpen: function(content) {
      content.connectSuccess();
      if (content.imm != null) {
        return;
      }
      sendAllRequest(content);
    }
    /**
     *
     * @param {WSClient}content
     * @param {{data: ArrayBuffer}}message
     * @returns {null|{id:int, status:int, data:DataView}}
     */
    , onMessage: function(content, message) {
      var data = new DataView(message.data);
      var reqid = data.getUint32(0);
      var status = data.getUint8(4);

      if (reqid == pushID ) {
        if (typeof content.onPush == "function") {
          data = new Uint8Array(message.data, 5, message.data.byteLength -5);
          content.onPush(data);
        }
        return null;
      }

      var req = content.requests[reqid.toString()];

      data = new Uint8Array(message.data, 5, message.data.byteLength -5);
      if (req == null || req == undefined) {
        return {id: reqid, status: status, data:data};
      }

      if (typeof req.comp === "function") {
        req.comp();
      }
      if (status !== 0 && typeof req.fail === "function") {
        var str = new StringView(data);
        req.fail(str.toString()); //string
      }
      if (status === 0 && typeof req.suc === "function") {
        req.suc(data); //Uint8Array
      }
      delete content.requests[reqid.toString()];
      return null;
    }
  });



  function onMessageImm(content, message) {
    var res = content.protocol.onMessage(content, message);
    if (res == null || res == undefined) {
      console.error("imm message error");
    }
    if (typeof content.imm.comp === "function") {
      content.imm.comp();
    }
    if (res.status !== 0 && typeof content.imm.fail === "function") {
      content.imm.fail((new StringView(res.data)).toString()); //string
    }
    if (res.status === 0 && typeof content.imm.suc === "function") {
      content.imm.suc(res.data); //Uint8Array
    }

    // reset onMessage
    content.onMessage = function(message) {
      content.protocol.onMessage(content, message);
    };
    content.imm = null;
    sendAllRequest(content);
  }

  function getRequestID(content) {
    if (((++content.reqID) & 0xffffffff) < reqIDstart) {
      content.reqID = reqIDstart;
    }
    return content.reqID;
  }

  function connect(content) {
    var ws = content.ws = new WebSocket(content.url);
    ws.binaryType = "arraybuffer";
    ws.onmessage = function(message){content.onMessage(message)};
    var timer = setTimeout(function(){
      ws.timeout();
    }, 30000);
    ws.onopen = function(event){
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
      content.onOpen(event)
    };
    ws.onclose = function(event) {
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
      if (ws.readyState != WebSocket.OPEN) {
        return;
      }
      this.websocket.close(1000);
      content.connectFailed("connect closed");
    };
    ws.onerror = function(event) {
      console.error("connect error---" + JSON.stringify(event));
      // 会自动调用 onclose
    };
    ws.timeout = function(event) {
      timer = null;
      this.onopen = function(event){};
      this.onclose = function(event){};
      this.onerror = function(event){};
      this.onmessage = function(event){};
      content.ws = null;
      content.connectFailed("connect timeout");
    };
  }

  ns.WSClient = function() {
    this.requests = Object.create(null);
    this.imm = null;
    this.reqID = reqIDstart;

    this.exponentHex = null;
    this.modulusHex = null;
    this.symmetricKey = null;

    this.url = null;
    this.connectSuccess = function(){};
    this.connectFailed = function(){};

    /**
     *
     * @type {WebSocket}
     */
    this.ws = null;

    this.protocol = defaultProto;
    this.send = function(reqid, data){
      this.protocol.send(this, reqid, data);
    };
    this.onMessage = function(message) {
      this.protocol.onMessage(this, message);
    };
    this.onOpen = function(event) {
      this.protocol.onOpen(this);
    };

    this.onPush = function(Uint8Array_data){};
  };

  var pro = ns.WSClient.prototype;

  pro.setPublicKey = function(exponentHex, modulusHex) {
    this.modulusHex = modulusHex;
    this.exponentHex = exponentHex;
  };

  /**
   *
   * @param {string}url, ws(s)://xxx.xxx.xx:xxx/xxxx
   * @param {function()|null}onSuccess
   * @param {function(string)|null}onFailed
   */
  pro.setConnectArgs = function(url, onSuccess, onFailed) {
    this.url = url;
    this.connectSuccess = onSuccess;
    var that = this;
    this.connectFailed = function(str){
      for (var reqid in this.requests){
        setTimeout(
          (function(id){
            return function(){
              defaultProto.onMessage(that, defaultProto.buildFailedResponse(id
                , str))
            }
          })(reqid), 0);
      }
      if (typeof onFailed == "function") {
        onFailed(str);
      }
    };
  };

  /**
   *
   * @param {ArrayBuffer|string}request
   * @param {function(Uint8Array)|null}onSuccess
   * @param {function(string)|null}[onFailed]
   * @param {function()|null}[onComplete]
   */
  pro.sendRequestImmediately = function(request, onSuccess, onFailed, onComplete) {
    this.imm = {req: request, suc:onSuccess
      , fail:onFailed, comp:onComplete, reqid: immID};

    this.onMessage = function(message) {
      onMessageImm(this, message);
    };
    this.send(immID, request);
  };

  /**
   *
   * @param {ArrayBuffer|string}request
   * @param {function(Uint8Array)|null}onSuccess
   * @param {function(string)|null}[onFailed]
   * @param {function()|null}[onComplete]
   */
  pro.addRequest = function(request, onSuccess, onFailed, onComplete) {
    var reqid = getRequestID(this);
    onSuccess = onSuccess || null;
    onFailed = onFailed || null;
    onComplete = onComplete || null;
    this.requests[reqid.toString()] = {req: request, suc:onSuccess
      , fail:onFailed, comp:onComplete, reqid: reqid};
    if (this.ws != null && this.ws.readyState == WebSocket.OPEN) {
      this.send(reqid, request);
      return;
    }
    if (this.ws != null && this.ws.readyState == WebSocket.CONNECTING) {
      return;
    }
    connect(this);
  };

})(this);
