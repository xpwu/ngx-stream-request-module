<?php
/**
 * Created by PhpStorm.
 * User: xpwu
 * Date: 2017/12/26
 * Time: 上午12:28
 */

require_once("Pusher.inc");
require_once("DataPusher.inc");
require_once("PushState.inc");

$pusher = new \stm\DataPusher("this is push data---".time());
echo \stm\PushState::toString($pusher->pushTo("127.0.0.1:7999/2be7535300009e545a41c47a00000002"));
echo "\n";

