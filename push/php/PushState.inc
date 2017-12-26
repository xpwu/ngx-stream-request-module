<?php
/**
 * Created by PhpStorm.
 * User: xpwu
 * Date: 2017/12/25
 * Time: 下午11:33
 */

namespace stm;


final class PushState {
  const Success = 0;
  const TokenNotMatchHost = 1;
  const TokenNotExist = 2;
  const PushServerError = 3;
  const HostConnectionError = 10;
  const ElseError = 11;
  const PushTimeout = 12;
  const UrlError = 13;

  static public function toString($num) {
    switch ($num) {
      case 0: return "Success";
      case 1: return "TokenNotMatchHost";
      case 2: return "TokenNotExist";
      case 3: return "PushServerError";
      case 10: return "HostConnectionError";
      case 11: return "ElseError";
      case 12: return "PushTimeout";
      case 13: return "UrlError, which should be host:port/sessiontoken";
      default: return "UnknownError";
    }
  }
}