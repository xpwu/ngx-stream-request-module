<?php
/**
 * Created by PhpStorm.
 * User: xpwu
 * Date: 2017/12/26
 * Time: 上午12:27
 */

namespace stm;


class CloseConnectionPusher extends Pusher {

  function __construct(int $subProtocol = 1) {
    parent::__construct($subProtocol);
  }

  protected function subProtocolData(): string {
    // TODO: Implement subProtocolData() method.
    return "";
  }
}