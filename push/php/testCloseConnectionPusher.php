<?php
/**
 * Created by PhpStorm.
 * User: xpwu
 * Date: 2017/12/26
 * Time: 下午2:35
 */

require_once("Pusher.inc");
require_once("DataPusher.inc");
require_once ("CloseConnectionPusher.inc");
require_once("PushState.inc");

$pusher = new \stm\CloseConnectionPusher();
echo \stm\PushState::toString(
  $pusher->pushTo("127.0.0.1:7999/2be753530000a84c5a42028100000002"));
echo "\n";