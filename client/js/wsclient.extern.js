/**
 * Created by xpwu on 2016/11/22.
 */

/*
    this file only for IDE
 */

console.error("this file only for IDE");

function WSClient() {
  /**
   * This callback is displayed as a global member.
   * @callback pushCallback
   * @param {Uint8Array}
   */

  /**
   *
   * @type pushCallback
   */
  this.onPush = 0;
}

/**
 *
 * @param {string}url, ws(s)://xxx.xxx.xx:xxx/xxxx
 * @param {function()|null}onSuccess
 * @param {function(string)|null}onFailed
 */
WSClient.prototype.setConnectArgs = function(url, onSuccess, onFailed){};

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
WSClient.prototype.setBlockRequestOnConnected = function (request, onSuccess, onFailed, headers, onComplete) {};


/**
 *
 * @param {ArrayBuffer|string}body
 * @param {function(Uint8Array)|null}onSuccess
 * @param {function(string)|null}[onFailed]
 * @param {Object|null} [headers]
 * @param {function()|null}[onComplete]
 */
WSClient.prototype.addRequest = function(body, onSuccess, onFailed, headers, onComplete) {};