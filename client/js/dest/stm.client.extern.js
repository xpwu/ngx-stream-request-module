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

  /**
   *
   * @var {function(Object)}
   */
  this.onPushJson = null;
};

/**
 *
 * @param {number} connectTimeout  unit: s
 */
stm.Client.prototype.setConfig = function (connectTimeout){};

/**
 *
 * @param {string}url, ws(s)://xxx.xxx.xx:xxx/xxxx
 * @param {function()|null} [onSuccess]
 * @param {function(string)|null} [onFailed]
 */
stm.Client.prototype.setConnectArgs = function(url, onSuccess, onFailed){};

/**
 *
 * @param {Object|null} [body]
 * @param {function(Object)|null} [onSuccess]
 * S
 * @param {Object|null} [headers]
 * @param {function(string)|null} [onFailed]
 * @param {function()|null} [onComplete]
 */
stm.Client.prototype.addJsonRequest = function (body, onSuccess, headers, onFailed, onComplete) {};

/**
 *
 * @param {ArrayBuffer|string|null} [body]
 * @param {function(ArrayBuffer)|null} [onSuccess]
 * @param {Object|null} [headers]
 * @param {function(string)|null} [onFailed]
 * @param {function()|null} [onComplete]
 */
stm.Client.prototype.addRequest = function (body, onSuccess, headers, onFailed, onComplete) {};
