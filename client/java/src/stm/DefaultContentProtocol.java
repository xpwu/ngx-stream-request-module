package stm;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Map;

/**
 *
 * Created by xpwu on 2016/11/29.
 */

/**
 * content protocol:
 *    request ---
 *      reqid | headers | header-end-flag | data
 *        reqid: 4 bytes, net order;
 *        headers: < key-len | key | value-len | value > ... ;  [optional]
 *          key-len: 1 byte,  key-len = sizeof(key);
 *          value-len: 1 byte, value-len = sizeof(value);
 *        header-end-flag: 1 byte, === 0;                       [optional]
 *        data:       [optional]
 *
 *    response ---
 *      reqid | status | data
 *        reqid: 4 bytes, net order;
 *        status: 1 byte, 0---success, 1---failed
 *        data: if status==success, data=<app data>    [optional]
 *              if status==failed, data=<error reason>
 *
 */

class DefaultContentProtocol implements ContentProtocol {
  public Response parse(byte[] content){
    Response res = new Response();
    res.reqID = 0;
    for (int i = 0; i < 4; ++i) {
      res.reqID = (res.reqID << 8) + (content[i]&0xff);
    }
    res.status = content[4] == 0? Response.Status.Success : Response.Status.Failed;
    if (content.length <= 5) {
      return res;
    }
    try {
      res.data = Arrays.copyOfRange(content, 5, content.length);
    } catch (Exception e) {
      res.data = null;
    }
    return res;
  }

  public byte[] build(byte[] body, Map<String, String> headers, long reqID){
    int length = 4 + 1;
    if (body != null) {
      length += body.length;
    }
    if (headers != null) {
      for (Map.Entry<String, String> entry : headers.entrySet()) {
        byte[] key = null;
        byte[] value = null;
        try {
          key = entry.getKey().getBytes("UTF-8");
          value = entry.getValue().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
          return null;
        }
        if (key.length > 255 || value.length > 255) {
          return null;
        }
        length += 1 + key.length + 1 + value.length;
      }
    }

    byte[] request = new byte[length];
    request[0] = (byte) ((reqID & 0xff000000) >> 24);
    request[1] = (byte) ((reqID & 0xff0000) >> 16);
    request[2] = (byte) ((reqID & 0xff00) >> 8);
    request[3] = (byte) (reqID & 0xff);

    int pos = 4;
    if (headers != null) {
      for (Map.Entry<String, String> entry : headers.entrySet()) {
        byte[] key = null;
        byte[] value = null;
        try {
          key = entry.getKey().getBytes("UTF-8");
          value = entry.getValue().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
          return null;
        }
        if (key.length > 255 || value.length > 255) {
          return null;
        }
        request[pos] = (byte) key.length;
        pos++;
        System.arraycopy(key, 0, request, pos, key.length);
        pos += key.length;
        request[pos] = (byte) value.length;
        pos++;
        System.arraycopy(value, 0, request, pos, value.length);
        pos += value.length;
      }
    }
    request[pos] = 0; // header-end
    pos++;

    if (body != null) {
      System.arraycopy(body, 0, request, pos, body.length);
    }

    return request;
  }

  public byte[] buildFailedMessage(String error, long reqID){
    byte[] msg = null;
    try {
      byte[] err = error.getBytes("UTF-8");
      msg = new byte[err.length + 1 + 4];
      System.arraycopy(err, 0, msg, 5, err.length);
    }catch (UnsupportedEncodingException e) {
      msg = new byte[4 + 1];
    }
    msg[0] = (byte) ((reqID & 0xff000000) >> 24);
    msg[1] = (byte) ((reqID & 0xff0000) >> 16);
    msg[2] = (byte) ((reqID & 0xff00) >> 8);
    msg[3] = (byte) (reqID & 0xff);
    msg[4] = 1;

    return msg;
  }
}
