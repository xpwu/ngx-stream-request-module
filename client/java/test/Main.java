import stm.Client;

public class Main {

    public static void main(String[] args) {
	// write your code here
      Client client = new Client();
      client.setHostAndPort("127.0.0.1", 10003, new Client.NetCallback() {
        @Override
        public void onSuccess() {
          System.out.println("connect success");
        }

        @Override
        public void onFailed(String error) {
          System.out.println("connnect failed" + error);
        }
      });
      client.addRequest("add request".getBytes(), null, new Client.RequestCallback(){
        @Override
        public void onSuccess(byte[] data) {
          System.out.println("onSuccess" + new String(data));
        }
        public void onFailed(String error) {
          System.out.println("request failed" + error);
        }
        public void onComplete() {
          System.out.println("onComplete");
        }
      });
    }
}
