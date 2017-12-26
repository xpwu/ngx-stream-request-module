<?php
/**
 * Created by PhpStorm.
 * User: xpwu
 * Date: 2017/12/25
 * Time: 下午11:30
 */

namespace stm;

/**
 *
 * request:
 *  sequece | token | subprotocol | len | <data>
 *    sizeof(sequece) = 4. net order
 *    sizeof(token) = 32 . hex
 *    sizeof(subprotocol) = 1.
 *    sizeof(len) = 4. len = sizof(data) net order
 *    data: subprotocol request data
 *
 * response:
 *  sequece | state | len | <data>
 *    sizeof(sequece) = 4. net order
 *    sizeof(state) = 1.
 *              state = 0: success; 1: hostname error
 *               ; 2: token not exist; 3: server intelnal error
 *    sizeof(len) = 4. len = sizeof(data) net order
 *    data: subprotocol response data
 */

abstract class Pusher {

  function __construct(int $subProtocol) {
    $this->subProtocol_ = $subProtocol;
  }

  /**
   * @param string $sessionToken [host:port/sessiontoken]
   * @return int
   */
  public function pushTo(string $url): int {
    $re = parse_url($url);
    if ($re === false || !$re["host"] || !$re["port"] || !$re["path"]) {
      return PushState::UrlError;
    }

    if (!$this->fd($re["host"], $re["port"])) {
      return PushState::HostConnectionError;
    }

    $sessionToken = substr($re["path"], 1); // trim the first '/'

    $seq = time();
    $data = $this->subProtocolData();

    $request = pack("N", $seq).$sessionToken.pack("C", $this->subProtocol_)
      .pack("N", strlen($data)).$data;

    $fd = $this->fd_;

    stream_set_timeout($fd, 5);
    if (!fwrite($fd, $request)) {
      return PushState::ElseError;
    }
    $status = stream_get_meta_data($this->fd_);
    if ($status['timed_out']) {
      return PushState::PushTimeout;
    }

    stream_set_timeout($fd, 5);
    $response = unpack("Nseq/Cst/Nlen", fread($fd, 9));
    $status = stream_get_meta_data($this->fd_);
    if ($status['timed_out']) {
      return PushState::PushTimeout;
    }

    if ($seq != $response["seq"]) {
      return PushState::PushServerError;
    }
    if ($response["len"] !== 0) {
      $this->result_ = fread($fd, $response["len"]);
    }

    return $response["st"];
  }

  private function fd(string $host, int $port):bool {
    try {
      $this->fd_ = pfsockopen($host, $port, $errNO, $errStr, 10);
    }catch (\Exception $e) {
      return false;
    }
    return true;
  }

  abstract protected function subProtocolData():string ;

  public function result():string {
    return $this->result_;
  }

  private $fd_;
  private $result_="";
  private $subProtocol_;

}