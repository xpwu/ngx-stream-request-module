


let ClientImpl = require("client").Client;


class Client {
  constructor() {
    /**
     *
     * @type {Client}
     * @private
     */
    this.impl_ = new ClientImpl();
  }

  /**
   *
   * @return {Promise.<resolve({})>}
   */
  pushJson() {
    return new Promise((resolve)=>{
      this.impl_.onPushJson = function (json) {
        resolve(json);
      }
    });
  }

  /**
   *
   * @param {number} connectTimeout  unit: s
   */
  setConfig(connectTimeout) {
    this.impl_.setConfig(connectTimeout);
  }

  /**
   *
   * @param {string}args ws(s)://xxxxx:xx
   * @return {Promise.<resolve, reject(string)>}
   */
  setConnectArgs(args) {
    return new Promise((resolve, reject)=>{
      this.impl_.setConnectArgs(args, ()=>{
        resolve();
      }, (error)=>{
        reject(error);
      })
    });
  }

  /**
   *
   * @param {{}|null}body
   * @param {{}|null}headers
   * @return {Promise.<resolve({}), reject(string)>}
   */
  addJsonRequest(body, headers) {
    return new Promise((resolve, reject)=>{
      this.impl_.addJsonRequest(body, (res)=>{
        resolve(res);
      }, headers
      , (error)=>{
        reject(error);
      }, null);
    });
  }

  // /**
  //  *
  //  * @param {ArrayBuffer|string|null}body
  //  * @param {{}|null}headers
  //  * @return {Promise.<resolve({}), reject(string)>}
  //  */
  // addRequest(body, headers) {
  //   return new Promise((resolve, reject)=>{
  //     this.impl_.addRequest(body, (res)=>{
  //       resolve(res);
  //     }, headers
  //     , (error)=>{
  //       reject(error);
  //     });
  //   })
  // }
}

module.exports.Client = Client;
