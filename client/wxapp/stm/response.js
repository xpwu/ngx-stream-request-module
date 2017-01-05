/**
 * Created by xpwu on 2016/12/1.
 */


// (function (ns) {
//   "use strict";

  // var stm = ns.stm = ns.stm || {};

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

  // stm.Response = Response;
  // stm.Response.State = state;

  module.exports.Response = Response;
  module.exports.Response.State = state;

// })(this);