/**
 * Created by xpwu on 2016/12/1.
 */


// (function (ns) {
//   "use strict";
//   var stm = ns.stm = ns.stm || {};

let StringView = require("stringview.js").StringView;
  let Response = require("response.js").Response;
  let WXWebSocket = require("wxwebsocket.js").WXWebSocket;

  let stm={};
  stm.Response = Response;
  stm.StringView = StringView;

  let DefaultContentProtocol = {
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

  module.exports.DefaultContentProtocol = DefaultContentProtocol;

// })(this);
