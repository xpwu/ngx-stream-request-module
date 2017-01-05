

function WXWebSocket(url) {
  this.onmessage = function(data){};
  this.onopen = function(data){};
  this.onclose = function(data){};
  this.onerror = function(data){};

  this.url = url;
  this.readyState = WXWebSocket.CONNECTING;

  let that = this;

  wx.connectSocket({
    url: url
  });

  wx.onSocketOpen(function(res) {
    that.readyState = WXWebSocket.OPEN;
    that.onopen(res);
  });

  wx.onSocketError(function(res){
    that.readyState = WXWebSocket.CLOSED;
    that.onerror(res);
  });

  wx.onSocketMessage(function(res) {
    that.onmessage(res);
  });

  wx.onSocketClose(function(res) {
    that.readyState = WXWebSocket.CLOSED;
    that.onclose(res);
  });
}

/**
@param {String|ArrayBuffer|ArrayBufferView|Blob} data
*/
WXWebSocket.prototype.send = function(msg) {
    wx.sendSocketMessage({
      data:msg
    });
};
/**
@param {number} [code]
@param {string} [reason]
*/
WXWebSocket.prototype.close = function(code,reason) {
    wx.closeSocket();
};

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
