<?php
/**
 * Created by PhpStorm.
 * User: xpwu
 * Date: 2017/12/26
 * Time: 上午12:23
 */

namespace stm;


class DataPusher extends Pusher {
  function __construct(string $data = "", int $subProtocol = 0) {
    parent::__construct($subProtocol);
    $this->data_ = $data;
  }

  protected function subProtocolData(): string {
    // TODO: Implement subProtocolData() method.
    return $this->data_;
  }

  private $data_;
}