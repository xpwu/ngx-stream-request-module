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

    client.setHostAndPort("127.0.0.1", 10003, new Client.NetCallback() {
      @Override
      public void onSuccess() {
        System.out.println("connect success");
      }

      @Override
      public void onFailed(String error) {
        System.out.println("connnect failed---" + error);
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
        System.out.println("onComplete");
      }
    });

    headers.clear();
    headers.put("h", "test");
    headers.put("ua", "add request ua");
    client.addRequest(null, headers, new Client.RequestCallback(){
      @Override
      public void onSuccess(byte[] data) {
        System.out.println("onSuccess---" + new String(data));
      }
      public void onFailed(String error) {
        System.out.println("request failed---" + error);
      }
      public void onComplete() {
        System.out.println("onComplete");
      }
    });

    MainThreadLooper.loop();
  }
}
