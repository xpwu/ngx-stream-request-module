<?php


/**
 *
 * request:
 *  sequece | token | len | data
 *    sizeof(sequece) = 4. net order
 *    sizeof(token) = 32 . hex
 *    sizeof(len) = 4. len = sizof(data) net order
 *
 * response:
 *  sequece | state
 *    sizeof(sequece) = 4. net order
 *    sizeof(state) = 1. --- 0: success; 1: hostname error; 2: token not exist
 *
 */


namespace STM {
  final class PushState {
    const Success = 0;
    const TokenNotMatchHost = 1;
    const TokenNotExist = 2;
    const HostConnectionError = 3;
    const PushServerError = 4;
    const ElseError = 5;
    const PushTimeout = 6;

    static public function toString($num) {
      switch ($num) {
        case 0: return "Success";
        case 1: return "TokenNotMatchHost";
        case 2: return "TokenNotExist";
        case 3: return "HostConnectionError";
        case 4: return "PushServerError";
        case 5: return "ElseError";
        case 6: return "PushTimeout";
        default: return "unknown";
      }
    }
  }

  class PushClient {
    /**
     * PushClient constructor.
     * @param string $ip
     * @param int $port
     * @param bool [$pfd]; 是否使用长连接
     */
    function __construct($ip, $port, $pfd = false) {
      $this->ip_ = $ip;
      $this->port_ = $port;
      $this->fd_ = 0;
      $this->pfd_ = $pfd;
    }

    function __destruct() {
      if ($this->fd_ != 0) {
        fclose($this->fd_);
      }
    }

    /**
     * @param string $token
     * @param string $buffer
     * @return int
     */
    public function push($token, $buffer) {

      if ($this->fd_ == 0) {
        try {
          if ($this->pfd_) {
            $this->fd_ = pfsockopen($this->ip_, $this->port_, $errNO, $errstr, 10);
          } else {
            $this->fd_ = fsockopen($this->ip_, $this->port_, $errNO, $errstr, 10);
          }
        }catch (\Exception $e) {
          return PushState::HostConnectionError;
        }
      }

      $fd = $this->fd_;
      if (!$fd) {
        return PushState::HostConnectionError;
      }

      $seq = time();
      $protocol = pack("N", $seq).$token.pack("N", strlen($buffer)).$buffer;

      stream_set_timeout($fd, 5);
      if (!fwrite($fd, $protocol)) {
        return PushState::ElseError;
      }
      $status = stream_get_meta_data($this->fd_);
      if ($status['timed_out']) {
        return PushState::PushTimeout;
      }

      stream_set_timeout($fd, 5);
      $response_id = unpack("Nseq", fread($fd, 4));
      $status = stream_get_meta_data($this->fd_);
      if ($status['timed_out']) {
        return PushState::PushTimeout;
      }

      if ($seq != $response_id["seq"]) {
        return PushState::PushServerError;
      }

      return ord(fread($fd, 1));
    }

    private $ip_;
    private $port_;
    /**
     * @var resource
     */
    private $fd_;
    /**
     * @var boolean
     */
    private $pfd_;
  }
}


