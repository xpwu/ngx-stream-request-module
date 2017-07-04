/**
 * Created by xpwu on 2016/12/1.
 */

  let StringView = require("stringview.js").StringView;
  let DefaultContentProtocol = require("defaultcontentprotocol.js").DefaultContentProtocol;
  let ContentProtocol = require("contentprotocol.js").ContentProtocol;
  let Response = require("response.js").Response;
  let WXWebSocket = require("wxwebsocket.js").WXWebSocket;

  let stm={};
  stm.Response = Response;
  stm.ContentProtocol = ContentProtocol;
  stm.DefaultContentProtocol = DefaultContentProtocol;
  stm.StringView = StringView;
  
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
  var pushID = 1; // need equal server
  
  function Client() {
    function init(client) {
      /**
       * @type {WebSocket}
       */
      client.net_ = null;
      client.netArgs_ = "";
      client.requests_ = Object.create(null);
      client.protocol_ = ContentProtocol.extend(DefaultContentProtocol);
      client.reqID_ = reqIDstart;
      client.onConnectionSuc_ = function () {};
      client.onConnectionFaild_ = function (error) {};
      client.normalOnMessage_ = function (data) {};
      client.connectTimeout_ = 30;
    }
    init(this);

    /**
     *
     * @param {ArrayBuffer}data
     */
    this.onPush = function (data) {};
    /**
     *
     * @var {function(Object)}
     */
    this.onPushJson = null
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
   * @param {boolean}needPause
   */
  pro.setConnectArgs = function(args, onSuccess, onFailed, needPause){
    this.netArgs_ = args;
    this.onConnectionFaild_ = onFailed || function (error) {};
    this.onConnectionSuc_ = onSuccess || function () {};
  };

  /**
   *
   * @param {number} connectTimeout  unit: s
   */
  pro.setConfig = function (connectTimeout) {
    this.connectTimeout_ = connectTimeout;
  };

  /**
   * This callback is displayed as a global member.
   * @callback successCallback
   * @param {ArrayBuffer}
   * @return {boolean|null}
   */

/**
 * This callback is displayed as a global member.
 * @callback successJsonCallback
 * @param {Object}
 * @return {boolean|null}
 */

/**
 *
 * @param {Object|null} [body]
 * @param {function(Object)|null} [onSuccess]
 * @param {Object|null} [headers]
 * @param {function(string)|null} [onFailed]
 * @param {function()|null} [onComplete]
 */
  pro.addJsonRequest = function (body, onSuccess, headers, onFailed, onComplete) {
    let callback = (onSuccess==null)?null:function (response) {
      onSuccess(JSON.parse(new StringView(response).toString()));
    };

    this.addRequest(JSON.stringify((body===null)?null:body)
      , callback, headers, onFailed, onComplete);
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

    if (this.net_ != null && this.net_.readyState == WXWebSocket.OPEN) {
      Private(this).sendRequest(this.requests_[reqid.toString()]);
      return;
    }
    if (this.net_ != null && this.net_.readyState == WXWebSocket.CONNECTING) {
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
        client.onPushJson
        && client.onPushJson(JSON.parse(new StringView(response.data).toString()));
        return;
      }

      var request = client.requests_[response.reqID.toString()];
      if (request == null) {
        console.error("not find request for reqID<"+response.reqID+">");
        return;
      }

      request.onComplete();
      if (response.state != stm.Response.State.Success) {
        if (response.data === null || response.data === undefined) {
          request.onFailed("may be server error, but server has closed the error log");
        } else {
          request.onFailed((new StringView(response.data)).toString());
        }
      } else {
        request.onSuccess(response.data);
      }
      delete client.requests_[response.reqID.toString()];
    };

    this.client_.net_ = new WXWebSocket(this.client_.netArgs_);
    client.net_.haserror = false; // 添加一项WebSocket没有的属性
    client.net_.binaryType = "arraybuffer";
    client.net_.onmessage = function (event) {
      client.normalOnMessage_(event.data);
    };

    var timer = setTimeout(function(){
      client.net_.timeout();
    }, client.connectTimeout_*1000);

    var that = this;
    client.net_.onopen = function(event){
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
      client.protocol_.onOpen(client.onConnectionSuc_);

      that.sendAllRequest();
    };

    client.net_.onclose = function(event) {
      if (timer != null) {
        clearTimeout(timer);
        timer = null;
      }
      // readyState 的状态改变会先于onclose的执行
      // if (client.net_.readyState != WebSocket.OPEN) {
      //   return;
      // }
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

    this.errorAllRequest(errorstr);

    client.onConnectionFaild_(errorstr);
  };

  Client.StringView = StringView;
  module.exports.Client = Client;

