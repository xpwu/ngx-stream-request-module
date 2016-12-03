import stm.Client;

import java.util.HashMap;
import java.util.Map;

public class Main {

  public static void main(String[] args) {

    Client client = new Client();

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

    client.setConnectHostAndPort("127.0.0.1", 10003, new Client.NetCallback() {
      @Override
      public void onSuccess() {
        System.out.println("connect success");
      }

      @Override
      public void onFailed(String error) {
        System.out.println("connnect failed---" + error);
      }
    });

    client.setBlockRequestOnConnected("block message".getBytes(), null
      , new Client.BlockRequestCallback(){
      @Override
      public boolean onSuccess(byte[] data) {
        System.out.println("onSuccess---" + new String(data));
        return true;
      }
      public void onFailed(String error) {
        System.out.println("request failed---" + error);
      }
      public void onComplete() {
        System.out.println("request block message complete");
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
