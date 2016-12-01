/**
 * Created by xpwu on 2016/11/22.
 */

/*
    this file only for IDE
 */

console.error("this file only for IDE");

stm = stm || {};

stm.Client = function () {
  /**
   * @callback pushCallback
   * @param {ArrayBuffer}
   */

  /**
   *
   * @type pushCallback
   */
  this.onPush = 0;
};

/**
 *
 * @param {string}url, ws(s)://xxx.xxx.xx:xxx/xxxx
 * @param {function()|null} [onSuccess]
 * @param {function(string)|null} [onFailed]
 */
stm.Client.prototype.setConnectArgs = function(url, onSuccess, onFailed){};

/**
 * This callback is displayed as a global member.
 * @callback successCallback
 * @param {ArrayBuffer}
 * @return {bool}
 */

/**
 *
 * @param {ArrayBuffer|string|null} [body]
 * @param {successCallback|null} [onSuccess]
 * @param {function(string)|null} [onFailed]
 * @param {Object|null} [headers]
 * @param {function()|null}[onComplete]
 */
stm.Client.prototype.setBlockRequestOnConnected = function(body, onSuccess
  , headers, onFailed, onComplete) {};


/**
 *
 * @param {ArrayBuffer|string|null} [body]
 * @param {function(ArrayBuffer)|null} [onSuccess]
 * @param {Object|null} [headers]
 * @param {function(string)|null} [onFailed]
 * @param {function()|null} [onComplete]
 */
stm.Client.prototype.addRequest = function (body, onSuccess, headers, onFailed, onComplete) {};
