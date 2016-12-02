<?php
/**
 * Created by PhpStorm.
 * User: xpwu
 * Date: 2016/12/3
 * Time: 上午1:18
 */

require_once("StreamPush.inc");

$token = "2be7535300004326581a058f00000001";

if ($argc >= 2) {
  $token = $argv[1];
}

$data="this is test push---"."token=$token";

if ($argc >= 3) {
  $data=$argv[2];
}


$push = new STM\PushClient("127.0.0.1", 10002);
echo STM\PushState::toString($push->push($token, $data))."\n";
