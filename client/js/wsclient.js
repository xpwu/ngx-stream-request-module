/**
 * Created by xpwu on 16/10/12.
 */

(function(ns){
  "use strict";

  if (typeof StringView !== "function") {
    console.error("can not find StringView. you can find in https://developer.mozilla.org/en-US/Add-ons/Code_snippets/StringView or https://github.com/madmurphy/stringview.js");
    return;
  }

  /**
   *
   * @param {WSClient}content
   */
  function sendAllRequest(content) {
    for (var req in content.requests) {
      content.send(content.requests[req].reqid
        , content.requests[req].req
        , content.requests[req].headers);
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
     * @param {{key(string): value(string)}|null} headers
     */
    send: function(content, reqid, data, headers){console.error("protocol not implement send");}
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
   *    reqid | headers | header-end-flag | data
   *      reqid: 4 bytes, net order;
   *      headers: < key-len | key | value-len | value > ... ;  [optional]
   *        key-len: 1 byte,  key-len = sizeof(key);
   *        value-len: 1 byte, value-len = sizeof(value);
   *      header-end-flag: 1 byte, === 0;                       [optional]
   *      data:       [optional]
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
     * @returns {{data:ArrayBuffer}}
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
     * @param {{key(string): value(string)}|null} headers
     */
    , send: function(content, reqid, data, headers) {
      var that = this;
      if (typeof data !== "string" && !(data instanceof ArrayBuffer)) {
        setTimeout(function () {
          content.onMessage(that.buildFailedResponse(reqid
            , "data type is error, must be string or ArrayBuffer"))
        }, 0);
        return;
      }

      headers = headers || {};
      if (typeof headers !== "object") {
        setTimeout(function () {
          content.onMessage(that.buildFailedResponse(reqid
            , "headers must be a object type, for example {uri: '/location'}"))
        }, 0);
        return;
      }

      var headerLen = 1024;
      var headerBuffer = new ArrayBuffer(headerLen);
      var pos = 0;
      for (var key in headers) {
        if (!headers.hasOwnProperty(key)) {
          continue;
        }
        if (typeof key !== "string" || typeof headers[key] !== "string") {
          setTimeout(function () {
            content.onMessage(that.buildFailedResponse(reqid
              , "headers's key and property must be string"))
          }, 0);
          return;
        }
        if (key.length == 0 || headers[key].length==0) {
          continue;
        }
        if (pos + 1 + key.length + 1 + headers[key].length + 1/*end flag*/ > headerLen) {
          setTimeout(function () {
            content.onMessage(that.buildFailedResponse(reqid
              , "headers is too long"))
          }, 1);
          return;
        }
        (new DataView(headerBuffer)).setUint8(pos, key.length);
        pos++;
        (new Uint8Array(headerBuffer)).set((new StringView(key)).rawData, pos);
        pos += key.length;
        (new DataView(headerBuffer)).setUint8(pos, headers[key].length);
        pos++;
        (new Uint8Array(headerBuffer)).set((new StringView(headers[key])).rawData, pos);
        pos += headers[key].length;
      }
      (new DataView(headerBuffer)).setUint8(pos, 0);
      pos++;

      data = new StringView(data);
      var buffer = new ArrayBuffer(4 + data.rawData.byteLength + pos);
      (new DataView(buffer)).setUint32(0, reqid);
      (new Uint8Array(buffer)).set(new Uint8Array(headerBuffer, 0, pos), 4);
      (new Uint8Array(buffer)).set(data.rawData, 4+pos);

      content.ws.send(buffer);
    }
    /**
     *
     * @param {WSClient}content
     */
    , onOpen: function(content) {
      if (!sendBlockRequest(content)) {
        sendAllRequest(content);
      }
      content.connectSuccess();
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


  function onMessageBlock(content, message) {
    var success = true;
    var shouldSendMore = true;

    var res = content.protocol.onMessage(content, message);
    if (res == null || res == undefined) {
      console.error("BlockRequest parse response error");
      success = false;
    }

    if (res.status !== 0 ) {
      success = false;
    }
    shouldSendMore = shouldSendMore && success;

    if (typeof content.blockReq.comp === "function") {
      content.blockReq.comp();
    }
    if (res.status !== 0 && typeof content.blockReq.fail === "function") {
      content.blockReq.fail((new StringView(res.data)).toString()); //string
    }
    if (res.status === 0 && typeof content.blockReq.suc === "function") {
      shouldSendMore = shouldSendMore && !(content.blockReq.suc(res.data)===false); //Uint8Array
    }

    // reset onMessage
    content.onMessage = function(message) {
      content.protocol.onMessage(content, message);
    };
    content.block = false;

    if (!success) {
      for (var reqid in content.requests){
        setTimeout(
          (function(id){
            return function(){
              defaultProto.onMessage(content, defaultProto.buildFailedResponse(id
                , "BlockRequest error"))
            }
          })(reqid), 0);
      }
    }

    if (shouldSendMore) {
      sendAllRequest(content);
    }
  }

  /**
   *
   * @param client
   * @return {boolean} not send, return false; sending, return true
   */
  function sendBlockRequest(client) {
    if (client.blockReq == null) {
      return false;
    }

    client.block = true;
    client.onMessage = function(message) {
      onMessageBlock(this, message);
    };
    client.send(client.blockReq.reqid, client.blockReq.req
      , client.blockReq.headers);

    return true;
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
    // this.imm = null;
    this.reqID = reqIDstart;
    this.block = false;
    this.blockReq = null;

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
    this.send = function(reqid, data, headers){
      this.protocol.send(this, reqid, data, headers);
    };
    this.onMessage = function(message) {
      this.protocol.onMessage(this, message);
    };
    this.onOpen = function(event) {
      this.protocol.onOpen(this);
    };

    /**
     * This callback is displayed as a global member.
     * @callback pushCallback
     * @param {Uint8Array}
     */

    /**
     *
     * @type pushCallback
     */
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
   * This callback is displayed as a global member.
   * @callback successCallback
   * @param {Uint8Array}
   * @return {bool}
   */

  /**
   *
   * @param {ArrayBuffer|string}request
   * @param {successCallback}onSuccess
   * @param {function(string)|null}[onFailed]
   * @param {Object|null} [headers]
   * @param {function()|null}[onComplete]
   */
  pro.setBlockRequestOnConnected = function (request, onSuccess, onFailed, headers, onComplete) {
    this.blockReq = {req: request, suc:onSuccess
      , fail:onFailed, comp:onComplete, reqid: immID, headers: headers};
  };

  /**
   *
   * @param {ArrayBuffer|string}body
   * @param {function(Uint8Array)|null}onSuccess
   * @param {function(string)|null}[onFailed]
   * @param {Object|null} [headers]
   * @param {function()|null}[onComplete]
   */
  pro.addRequest = function(body, onSuccess, onFailed, headers, onComplete) {
    var reqid = getRequestID(this);
    onSuccess = onSuccess || null;
    onFailed = onFailed || null;
    onComplete = onComplete || null;

    this.requests[reqid.toString()] = {req: body, suc:onSuccess
      , fail:onFailed, comp:onComplete, reqid: reqid, headers: headers};

    if (this.block) {
      return;
    }

    if (this.ws != null && this.ws.readyState == WebSocket.OPEN) {
      this.send(reqid, body, headers);
      return;
    }
    if (this.ws != null && this.ws.readyState == WebSocket.CONNECTING) {
      return;
    }
    connect(this);
  };

})(this);
