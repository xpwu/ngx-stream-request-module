import stm.Client;

import java.io.ByteArrayInputStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class Main {

  public static void main(String[] args) {

    final Client client = new Client();

    client.setAsyncEventHandler(new Client.AsyncEventHandler() {
      @Override
      public void onFire() {
        MainThreadLooper.addHandler(new MainThreadLooper.Handler() {
          @Override
          public void run() {
            client.pump();
          }
        });
      }
    });

    client.setDelegate(new Client.Delegate() {
      @Override
      public void onPush(byte[] data) {
        System.out.println("onpush---" + new String(data));
      }
    });


    final String ca = "-----BEGIN CERTIFICATE-----\n" +
                    "MIIHyTCCBbGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEW\n" +
                    "MBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwg\n" +
                    "Q2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNh\n" +
                    "dGlvbiBBdXRob3JpdHkwHhcNMDYwOTE3MTk0NjM2WhcNMzYwOTE3MTk0NjM2WjB9\n" +
                    "MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMi\n" +
                    "U2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3Rh\n" +
                    "cnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUA\n" +
                    "A4ICDwAwggIKAoICAQDBiNsJvGxGfHiflXu1M5DycmLWwTYgIiRezul38kMKogZk\n" +
                    "pMyONvg45iPwbm2xPN1yo4UcodM9tDMr0y+v/uqwQVlntsQGfQqedIXWeUyAN3rf\n" +
                    "OQVSWff0G0ZDpNKFhdLDcfN1YjS6LIp/Ho/u7TTQEceWzVI9ujPW3U3eCztKS5/C\n" +
                    "Ji/6tRYccjV3yjxd5srhJosaNnZcAdt0FCX+7bWgiA/deMotHweXMAEtcnn6RtYT\n" +
                    "Kqi5pquDSR3l8u/d5AGOGAqPY1MWhWKpDhk6zLVmpsJrdAfkK+F2PrRt2PZE4XNi\n" +
                    "HzvEvqBTViVsUQn3qqvKv3b9bZvzndu/PWa8DFaqr5hIlTpL36dYUNk4dalb6kMM\n" +
                    "Av+Z6+hsTXBbKWWc3apdzK8BMewM69KN6Oqce+Zu9ydmDBpI125C4z/eIT574Q1w\n" +
                    "+2OqqGwaVLRcJXrJosmLFqa7LH4XXgVNWG4SHQHuEhANxjJ/GP/89PrNbpHoNkm+\n" +
                    "Gkhpi8KWTRoSsmkXwQqQ1vp5Iki/untp+HDH+no32NgN0nZPV/+Qt+OR0t3vwmC3\n" +
                    "Zzrd/qqc8NSLf3Iizsafl7b4r4qgEKjZ+xjGtrVcUjyJthkqcwEKDwOzEmDyei+B\n" +
                    "26Nu/yYwl/WL3YlXtq09s68rxbd2AvCl1iuahhQqcvbjM4xdCUsT37uMdBNSSwID\n" +
                    "AQABo4ICUjCCAk4wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAa4wHQYDVR0OBBYE\n" +
                    "FE4L7xqkQFulF2mHMMo0aEPQQa7yMGQGA1UdHwRdMFswLKAqoCiGJmh0dHA6Ly9j\n" +
                    "ZXJ0LnN0YXJ0Y29tLm9yZy9zZnNjYS1jcmwuY3JsMCugKaAnhiVodHRwOi8vY3Js\n" +
                    "LnN0YXJ0Y29tLm9yZy9zZnNjYS1jcmwuY3JsMIIBXQYDVR0gBIIBVDCCAVAwggFM\n" +
                    "BgsrBgEEAYG1NwEBATCCATswLwYIKwYBBQUHAgEWI2h0dHA6Ly9jZXJ0LnN0YXJ0\n" +
                    "Y29tLm9yZy9wb2xpY3kucGRmMDUGCCsGAQUFBwIBFilodHRwOi8vY2VydC5zdGFy\n" +
                    "dGNvbS5vcmcvaW50ZXJtZWRpYXRlLnBkZjCB0AYIKwYBBQUHAgIwgcMwJxYgU3Rh\n" +
                    "cnQgQ29tbWVyY2lhbCAoU3RhcnRDb20pIEx0ZC4wAwIBARqBl0xpbWl0ZWQgTGlh\n" +
                    "YmlsaXR5LCByZWFkIHRoZSBzZWN0aW9uICpMZWdhbCBMaW1pdGF0aW9ucyogb2Yg\n" +
                    "dGhlIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFBvbGljeSBhdmFp\n" +
                    "bGFibGUgYXQgaHR0cDovL2NlcnQuc3RhcnRjb20ub3JnL3BvbGljeS5wZGYwEQYJ\n" +
                    "YIZIAYb4QgEBBAQDAgAHMDgGCWCGSAGG+EIBDQQrFilTdGFydENvbSBGcmVlIFNT\n" +
                    "TCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOCAgEAFmyZ\n" +
                    "9GYMNPXQhV59CuzaEE44HF7fpiUFS5Eyweg78T3dRAlbB0mKKctmArexmvclmAk8\n" +
                    "jhvh3TaHK0u7aNM5Zj2gJsfyOZEdUauCe37Vzlrk4gNXcGmXCPleWKYK34wGmkUW\n" +
                    "FjgKXlf2Ysd6AgXmvB618p70qSmD+LIU424oh0TDkBreOKk8rENNZEXO3SipXPJz\n" +
                    "ewT4F+irsfMuXGRuczE6Eri8sxHkfY+BUZo7jYn0TZNmezwD7dOaHZrzZVD1oNB1\n" +
                    "ny+v8OqCQ5j4aZyJecRDjkZy42Q2Eq/3JR44iZB3fsNrarnDy0RLrHiQi+fHLB5L\n" +
                    "EUTINFInzQpdn4XBidUaePKVEFMy3YCEZnXZtWgo+2EuvoSoOMCZEoalHmdkrQYu\n" +
                    "L6lwhceWD3yJZfWOQ1QOq92lgDmUYMA0yZZwLKMS9R9Ie70cfmu3nZD0Ijuu+Pwq\n" +
                    "yvqCUqDvr0tVk+vBtfAii6w0TiYiBKGHLHVKt+V9E9e4DGTANtLJL4YSjCMJwRuC\n" +
                    "O3NJo2pXh5Tl1njFmUNj403gdy3hZZlyaQQaRwnmDwFWJPsfvw55qVguucQJAX6V\n" +
                    "um0ABj6y6koQOdjQK/W/7HW/lwLFCRsI3FU34oH7N4RDYiDK51ZLZer+bMEkkySh\n" +
                    "NOsF/5oirpt9P/FlUQqmMGqz9IgcgA38corog14=\n" +
                    "-----END CERTIFICATE-----\n";

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream finStream = new ByteArrayInputStream(ca.getBytes());
      X509Certificate caCertificate = (X509Certificate)cf.generateCertificate(finStream);
      client.setTrustX509Certificate(caCertificate);
    }catch (final CertificateException e) {
      return;
    }

    client.setConnectHostAndPort("ssl://www.xpwu.me", 10005, new Client.NetCallback() {
      @Override
      public void onSuccess() {
        System.out.println("connect success");
      }

      @Override
      public void onFailed(String error) {
        System.out.println("connnect failed---" + error);
//        client.addRequest("add request 2".getBytes(), null, new Client.RequestCallback(){
//          @Override
//          public void onSuccess(byte[] data) {
//            System.out.println("onSuccess---" + new String(data));
//          }
//          public void onFailed(String error) {
//            System.out.println("request failed---" + error);
//          }
//          public void onComplete() {
//            System.out.println("request <message null> complete");
//          }
//        });
      }
    });

    Map<String, String>headers = new HashMap<>(3);
    headers.put("h", "test");
    headers.put("ua", "add request ua");
    client.addRequest("add request".getBytes(), headers, new Client.RequestCallback(){
      @Override
      public void onSuccess(byte[] data) {
        System.out.println("onSuccess---" + new String(data));
      }
      public void onFailed(String error) {
        System.out.println("request failed---" + error);
      }
      public void onComplete() {
        System.out.println("request <message header> complete");
      }
    });

    Map<String, String>headers2 = new HashMap<>(3);
    headers2.put("h", "test");
    headers2.put("ua", "add request ua");
    client.addRequest(null, headers2, new Client.RequestCallback(){
      @Override
      public void onSuccess(byte[] data) {
        System.out.println("onSuccess---" + new String(data));
      }
      public void onFailed(String error) {
        System.out.println("request failed---" + error);
      }
      public void onComplete() {
        System.out.println("request <null header> complete");
      }
    });

    client.addRequest("add request 2".getBytes(), null, new Client.RequestCallback(){
      @Override
      public void onSuccess(byte[] data) {
        System.out.println("onSuccess---" + new String(data));
      }
      public void onFailed(String error) {
        System.out.println("request failed---" + error);
      }
      public void onComplete() {
        System.out.println("request <message null> complete");
      }
    });

    client.addRequest(null, null, new Client.RequestCallback(){
      @Override
      public void onSuccess(byte[] data) {
        System.out.println("onSuccess---" + new String(data));
      }
      public void onFailed(String error) {
        System.out.println("request failed---" + error);
      }
      public void onComplete() {
        System.out.println("request <null null> complete");
      }
    });


    Map<String, String>headers3 = new HashMap<>(3);
    headers3.put("h", "test");
    headers3.put("t", "ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);");


    client.addRequest("add request 2".getBytes(), headers3, new Client.RequestCallback(){
      @Override
      public void onSuccess(byte[] data) {
        System.out.println("onSuccess---" + new String(data));
      }
      public void onFailed(String error) {
        System.out.println("request failed---" + error);
      }
      public void onComplete() {
        System.out.println("request <null, long header> complete");
      }
    });

    MainThreadLooper.loop();
  }
}
