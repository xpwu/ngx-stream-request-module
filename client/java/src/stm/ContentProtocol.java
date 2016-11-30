package stm;

/**
 *
 * Created by xpwu on 2016/11/29.
 */

import java.util.Map;

interface ContentProtocol {
  public Response parse(byte[] content);
  public byte[] build(byte[] body, Map<String, String>headers, long reqID);
  public byte[] buildFailedMessage(String error, long reqID);
}
