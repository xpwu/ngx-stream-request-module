/**
 * Created by xpwu on 2016/12/1.
 */


(function (ns) {
  "use strict";

  var stm = ns.stm = ns.stm || {};

  var state = {Success: 0, Failed: 1};

  function Response() {
    /**
     *
     * @type {number}
     */
    this.reqID = 0;
    /**
     *
     * @type {number}
     */
    this.state = state.Success;
    /**
     *
     * @type {ArrayBuffer}
     */
    this.data = null;
  }

  stm.Response = Response;
  stm.Response.State = state;

})(this);
/**
 * Created by xpwu on 2016/12/1.
 */

(function (ns) {
  "use strict";

  var stm = ns.stm = ns.stm || {};

  stm.ContentProtocol = {
    /**
     *
     * @param {function()}callback
     */
    onOpen: function (callback) {
      callback();
    }

    /**
     *
     */
    , onClose: function () {

    }

    /**
     *
     * @param {ArrayBuffer}message
     * @return {*|Response}
     */
    , parse: function (message) {
      return new stm.Response();
    }

    /**
     *
     * @param {ArrayBuffer|string|null}body
     * @param {Object|null}headers
     * @param {number}reqID
     * @return {ArrayBuffer|string} success:ArrayBuffer; error: string
     */
    , build: function (body, headers, reqID) {
      return new ArrayBuffer(2);
    }

    /**
     *
     * @param {string}error
     * @param {number}reqID
     * @return {ArrayBuffer}
     */
    , buildFailedMessage: function(error, reqID) {
      return new ArrayBuffer(2);
    }

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

})(this);
/**
 * Created by xpwu on 2016/12/1.
 */


(function (ns) {
  "use strict";
  var stm = ns.stm = ns.stm || {};

  stm.DefaultContentProtocol = {
    /**
     *
     * @param {ArrayBuffer} message
     * @return {*|Response}
     */
    parse: function (message) {
      var response = new stm.Response();
      var messageView = new DataView(message);
      response.reqID = messageView.getUint32(0);
      response.state = (messageView.getUint8(4) == 0)? stm.Response.State.Success
        : stm.Response.State.Failed;
      response.data = message.slice(5);

      return response;
    }

    /**
     *
     * @param {ArrayBuffer|string|null}body
     * @param {Object|null}headers
     * @param {number}reqID
     * @return {ArrayBuffer|string}
     */
    , build: function (body, headers, reqID) {
      body = body || "";
      if (typeof body !== "string" && !(body instanceof ArrayBuffer)) {
        return "body type is error, must be string or ArrayBuffer";
      }

      headers = headers || {};
      if (typeof headers !== "object") {
        return "headers must be a object type, for example {uri: '/location'}";
      }

      var headerLen = 0;
      for (var key in headers) {
        if (!headers.hasOwnProperty(key)) {
          continue;
        }
        if (typeof key !== "string" || typeof headers[key] !== "string") {
          return "headers' key or property must be string";
        }

        if (key.length > 255) {
          return "length of headers' key <" + key + "> more than 255";
        }
        if (headers[key].length > 255) {
          return "length of headers' object <" + headers[key] + "> more than 255";
        }

        if (key.length == 0 || headers[key].length == 0) {
          continue;
        }
        headerLen += 1 + 1 + key.length + headers[key].length;
      }

      body = new StringView(body);
      var buffer = new ArrayBuffer(4 + body.rawData.byteLength + 1 + headerLen);
      (new DataView(buffer)).setUint32(0, reqID);

      var pos = 4;
      for (key in headers) {
        if (!headers.hasOwnProperty(key)) {
          continue;
        }

        (new DataView(buffer)).setUint8(pos, key.length);
        pos++;
        (new Uint8Array(buffer)).set((new StringView(key)).rawData, pos);
        pos += key.length;
        (new DataView(buffer)).setUint8(pos, headers[key].length);
        pos++;
        (new Uint8Array(buffer)).set((new StringView(headers[key])).rawData, pos);
        pos += headers[key].length;
      }
      (new DataView(buffer)).setUint8(pos, 0);
      pos++;

      (new Uint8Array(buffer)).set(body.rawData, pos);

      return buffer;
    }

    /**
     *
     * @param {string}error
     * @param {number}reqID
     * @return {ArrayBuffer}
     */
    , buildFailedMessage: function(error, reqID) {

      error = new StringView(error);
      var buffer = new ArrayBuffer(4 + error.rawData.byteLength + 1);
      (new DataView(buffer)).setUint32(0, reqID);
      (new DataView(buffer)).setUint8(4, stm.Response.State.Failed);
      (new Uint8Array(buffer)).set(error.rawData, 5);

      return buffer;
    }

  };

})(this);

/**
 * Created by xpwu on 2016/12/1.
 */


(function (ns) {
  "use strict";

  if (typeof StringView !== "function") {
    console.error("can not find StringView. this error maybe cause 'stm.Client is not a constructor'. you can find in https://developer.mozilla.org/en-US/Add-ons/Code_snippets/StringView or https://github.com/madmurphy/stringview.js");
    return;
  }
  
  function Request(body, onSuccess, headers, onFailed, onComplete, reqID) {
    /**
     *
     * @type {ArrayBuffer|string}
     */
    this.body = body || "";
    /**
     *
     * @type {Object}
     */
    this.headers = headers || {};
    /**
     *
     * @param {ArrayBuffer}data
     */
    this.onSuccess = onSuccess || function (data) {};
    /**
     *
     * @param {string} error
     */
    this.onFailed = onFailed || function (error) {};
    this.onComplete = onComplete || function () {};
    this.reqID = reqID;
  }

  var reqIDstart = 200;
  var blockID = reqIDstart-1;
  var pushID = 1; // need equal server
  
  function Client() {
    function init(client) {
      /**
       * @type {WebSocket}
       */
      client.net_ = null;
      client.netArgs_ = "";
      client.requests_ = Object.create(null);
      client.protocol_ = stm.ContentProtocol.extend(stm.DefaultContentProtocol);
      client.blockRequest_ = null;
      client.isBlock_ = false;
      client.reqID_ = reqIDstart;
      client.onConnectionSuc_ = function () {};
      client.onConnectionFaild_ = function (error) {};
      client.normalOnMessage_ = function (data) {};
    }
    init(this);

    // this.net_ = null;
    // this.netArgs_ = "";
    // this.requests_ = Object.create(null);
    // this.protocol_ = stm.ContentProtocol.extend(stm.DefaultContentProtocol);
    // this.blockRequest_ = null;
    // this.isBlock_ = false;
    // this.reqID_ = reqIDstart;
    // this.onConnectionSuc_ = function () {};
    // this.onConnectionFaild_ = function (error) {};
    // this.normalOnMessage_ = function (data) {};

    /**
     *
     * @param {ArrayBuffer}data
     */
    this.onPush = function (data) {}
  }

  function Private(obj) {
    return new PrivateWrapper(obj);
  }

  var pro = Client.prototype;

  /**
   *
   * @param {string}args ws(s)://xxxxx:xx
   * @param {function()|null}onSuccess
   * @param {function(string)|null}onFailed
   */
  pro.setConnectArgs = function(args, onSuccess, onFailed){
    this.netArgs_ = args;
    this.onConnectionFaild_ = onFailed || function (error) {};
    this.onConnectionSuc_ = onSuccess || function () {};
  };

  /**
   * This callback is displayed as a global member.
   * @callback successCallback
   * @param {ArrayBuffer}
   * @return {bool|null}
   */

  /**
   *
   * @param {ArrayBuffer|string|null} [body]
   * @param {successCallback|null} [onSuccess]
   * @param {Object|null} [headers]
   * @param {function(string)|null} [onFailed]
   * @param {function()|null} [onComplete]
   */
  pro.setBlockRequestOnConnected = function(body, onSuccess, headers, onFailed, onComplete) {
    this.blockRequest_ = new Request(body, onSuccess, headers, onFailed, onComplete, blockID);
  };

  /**
   *
   * @param {ArrayBuffer|string|null} [body]
   * @param {function(ArrayBuffer)|null} [onSuccess]
   * @param {Object|null} [headers]
   * @param {function(string)|null} [onFailed]
   * @param {function()|null} [onComplete]
   */
  pro.addRequest = function (body, onSuccess, headers, onFailed, onComplete) {
    if (this.netArgs_ == null) {
      if (typeof onComplete === "function") {
        onComplete();
      }
      if (typeof onFailed === "function") {
        onFailed("net args not set");
      }
      return;
    }

    var reqid = Private(this).getReqID();
    this.requests_[reqid.toString()] = new Request(body, onSuccess, headers
      , onFailed, onComplete, reqid);

    if (this.isBlock_) {
      return;
    }

    if (this.net_ != null && this.net_.readyState == WebSocket.OPEN) {
      Private(this).sendRequest(this.requests_[reqid.toString()]);
      return;
    }
    if (this.net_ != null && this.net_.readyState == WebSocket.CONNECTING) {
      return;
    }
    Private(this).connect();
  };

  //-------------- private -------------

  function postTask(callback) {
    setTimeout(callback, 0);
  }

  /**
   *
   * @param {Client}client
   * @constructor
   */
  function PrivateWrapper(client) {
    /**
     *
     * @type {Client}
     * @private
     */
    this.client_ = client;
  }

  var privatePro = PrivateWrapper.prototype;

  /**
   *
   * @return {number|*}
   */
  privatePro.getReqID = function () {
    this.client_.reqID_++;
    if (this.client_.reqID_ < reqIDstart) {
      this.client_.reqID_ = reqIDstart;
    }
    return this.client_.reqID_;
  };

  /**
   *
   * @param {Request}request
   */
  privatePro.sendRequest = function (request) {
    var client = this.client_;
    var data = client.protocol_.build(request.body, request.headers, request.reqID);

    if (typeof data == "string") {
      postTask(function () {
        var error = client.protocol_.buildFailedMessage(data, request.reqID);
        client.net_.onmessage({data: error});
      });
      return;
    }

    client.net_.send(data);
  };

  privatePro.connect = function () {
    var client = this.client_;
    this.client_.normalOnMessage_ = function (data) {

      var response = client.protocol_.parse(data);
      if (response.reqID == pushID) {
        client.onPush(response.data);
        return;
      }

      var request = client.requests_[response.reqID.toString()];
      if (request == null) {
        console.error("not find request for reqID<"+response.reqID+">");
        return;
      }

      request.onComplete();
      if (response.state != stm.Response.State.Success) {
        request.onFailed((new StringView(response.data)).toString());
      } else {
        request.onSuccess(response.data);
      }
      delete request[response.reqID.toString()];
    };

    this.client_.net_ = new WebSocket(this.client_.netArgs_);
    client.net_.haserror = false; // 添加一项WebSocket没有的属性
    client.net_.binaryType = "arraybuffer";
    client.net_.onmessage = function (event) {
      client.normalOnMessage_(event.data);
    };

    var timer = setTimeout(function(){
      client.net_.timeout();
    }, 30000);

    var that = this;
    client.net_.onopen = function(event){
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
      if (client.blockRequest_ != null) {
        that.sendBlockRequest();
      } else {
        that.sendAllRequest();
      }

      client.protocol_.onOpen(client.onConnectionSuc_);
    };

    client.net_.onclose = function(event) {
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
      if (client.net_.readyState != WebSocket.OPEN) {
        return;
      }
      client.net_.close(1000);
      client.protocol_.onClose();
      if (!client.net_.haserror) {
        client.net_.haserror = false;
        that.netError("connection closed by peer or connection error");
      }
    };

    client.net_.onerror = function(event) {
      // 部分错误可能会自动调用 onclose
      client.net_.haserror = true;

      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }

      that.netError("connect error---" + JSON.stringify(event));
    };

    client.net_.timeout = function(event) {
      timer = null;
      this.onopen = function(event){};
      this.onclose = function(event){};
      this.onerror = function(event){};
      this.onmessage = function(event){};
      client.net_ = null;

      that.netError("connect timeout");
    };

  };

  privatePro.sendAllRequest = function () {
    var client = this.client_;
    for (var req in client.requests_) {
      this.sendRequest(client.requests_[req]);
    }
  };

  privatePro.sendBlockRequest = function () {
    var client = this.client_;
    client.isBlock_ = true;
    var that = this;

    var blockOnMessage = function (data) {
      var response = client.protocol_.parse(data);

      var sendMore = true;
      var isSuc = true;

      var request = client.blockRequest_;

      request.onComplete();
      if (response.state != stm.Response.State.Success) {
        isSuc = false;
        request.onFailed((new StringView(response.data)).toString());
      } else {
        sendMore = !(request.onSuccess(response.data)===false);
      }
      sendMore = sendMore && isSuc;

      if (!isSuc) {
        that.errorAllRequest("block request error---"
          + (new StringView(response.data)).toString());
      }

      if (sendMore) {
        that.sendAllRequest();
      } else if (isSuc) {
        that.errorAllRequest("block request stop this request continuing");
      }

      client.isBlock_ = false;
      client.net_.onmessage = function (event) {
        client.normalOnMessage_(event.data);
      }
    };

    client.net_.onmessage = function (event) {
      blockOnMessage(event.data);
    };

    this.sendRequest(client.blockRequest_);
  };

  privatePro.errorAllRequest = function (error) {
    var client = this.client_;
    for (var req in client.requests_) {
      (function (id) {
        postTask(function () {
          client.normalOnMessage_(client.protocol_.buildFailedMessage(error, id));
        });
      })(Number(req));
    }
  };

  privatePro.netError = function (errorstr) {
    var client = this.client_;

    if (client.isBlock_) {
      postTask(function () {
        var error = client.protocol_.buildFailedMessage(errorstr, blockID);
        client.net_.onmessage({data: error});
      });
    }
    this.errorAllRequest(errorstr);

    client.onConnectionFaild_(errorstr);
  };

  var stm = ns.stm = ns.stm || {};
  stm.Client = Client;

})(this);
