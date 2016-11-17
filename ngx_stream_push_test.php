<?php

$fd=0;
try {
  $fd = fsockopen("127.0.0.1", 10002, $errNO, $errstr, 10);
} catch(\Exception $e) {
  echo $e."\n";
  exit(1);
}

$seq = time();
$token = "2be7535300004326581a058f00000001";

if ($argc >= 2) {
	$token = $argv[1];
}

$data="this is test push---".$seq."token=$token";

if ($argc >= 3) {
	$data=$argv[2];
}

echo $data."\n";

$protocol = pack("N", $seq).$token.pack("N", strlen($data)).$data;

fwrite($fd, $protocol);

stream_set_timeout($fd, 5);

$response_id = unpack("Nseq", fread($fd, 4));

if ($seq != $response_id["seq"]) {
  echo "error--seq".$seq.", while receive ".$response_id["seq"]."\n";
} else {
  echo "seq ==\n";
}

echo ord(fread($fd, 1))."\n";

