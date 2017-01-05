/**
 * Created by xpwu on 2016/12/1.
 */

// (function (ns) {
//   "use strict";

//   var stm = ns.stm = ns.stm || {};

  let ContentProtocol = {
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

  module.exports.ContentProtocol = ContentProtocol;

// })(this);