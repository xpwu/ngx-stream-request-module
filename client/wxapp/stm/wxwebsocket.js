

function TranVersion(vstr) {
  let ver = vstr.split(".");
  let version = 0;
  let factor = 1;
  for(let i = ver.length; i > 0; --i) {
    version += ver[i-1] * factor;
    factor *= 100;
  }

  return version;
}

class WxWebSocketImpl {
  constructor() {
    this.onmessage = function(data){};
    this.onopen = function(data){};
    this.onclose = function(data){};
    this.onerror = function(data){};

    this.readyState = WXWebSocket.CONNECTING;
  }

  /**
   @param {String|ArrayBuffer|ArrayBufferView|Blob} msg
   */
  send(msg){}

  /**
   @param {number} [code]
   @param {string} [reason]
   */
  close(code, reason){}
}

class WxWebSocketImplless170 extends WxWebSocketImpl {
  constructor(url) {
    super();

    wx.connectSocket({
      url: url
    });

    wx.onSocketOpen((res)=>{
      this.readyState = WXWebSocket.OPEN;
      this.onopen(res);
    });

    wx.onSocketError((res)=>{
      this.readyState = WXWebSocket.CLOSED;
      this.onerror(res);
    });

    wx.onSocketMessage((res)=>{
      this.onmessage(res);
    });

    wx.onSocketClose((res)=>{
      this.readyState = WXWebSocket.CLOSED;
      this.onclose(res);
    });
  }

  send(msg) {
    wx.sendSocketMessage({
      data: msg
    });
  }

  close(code,reason) {
    wx.closeSocket({code:code, reason:reason});
  };
}

class WxWebSocketImpl170 extends WxWebSocketImpl {
  constructor(url) {
    super();

    this.task = wx.connectSocket({
      url: url
    });

    this.task.onOpen((res)=>{
      this.readyState = WXWebSocket.OPEN;
      this.onopen(res);
    });

    this.task.onClose((res)=>{
      this.readyState = WXWebSocket.CLOSED;
      this.onclose(res);
    });

    this.task.onError((res)=>{
      this.readyState = WXWebSocket.CLOSED;
      this.onerror(res);
    });

    this.task.onMessage((res)=>{
      this.onmessage(res);
    });
  }

  send(msg) {
    this.task.send({
      data: msg
    });
  }

  close(code,reason) {
    this.task.close({code:code, reason:reason});
  };
}


class WXWebSocket {

  constructor(url) {
    let res = wx.getSystemInfoSync();
    if (res.SDKVersion && TranVersion(res.SDKVersion) >= 10700) {
      this.impl_ = new WxWebSocketImpl170(url);
    } else  {
      this.impl_ = new WxWebSocketImplless170(url);
    }
  }

  set onmessage(f) {
    this.impl_.onmessage = f;
  }

  set onopen(f) {
    this.impl_.onopen = f;
  }

  set onclose(f) {
    this.impl_.onclose = f;
  }

  set onerror(f) {
    this.impl_.onerror = f;
  }

  get readyState() {
    return this.impl_.readyState;
  }

  /**
  @param {String|ArrayBuffer|ArrayBufferView|Blob} msg
  */
  send(msg) {
    this.impl_.send(msg);
  };

  /**
  @param {number} [code]
  @param {string} [reason]
  */
  close(code,reason) {
    this.impl_.close(code, reason);
  };
}

/**
@static
@type {number}
@const
*/
WXWebSocket.CONNECTING = 0;
/**
@static
@type {number}
@const
*/
WXWebSocket.OPEN = 1;
/**
@static
@type {number}
@const
*/
WXWebSocket.CLOSING = 2;
/**
@static
@type {number}
@const
*/
WXWebSocket.CLOSED = 3;


module.exports.WXWebSocket = WXWebSocket;
