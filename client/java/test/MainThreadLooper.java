import java.util.LinkedList;
import java.util.List;

/**
 *
 * Created by xpwu on 2016/11/30.
 */

public class MainThreadLooper {
  static interface Handler {
    public void run();
  }

  static private final List<Handler> queue = new LinkedList<>();

  static void addHandler(Handler handler) {
    synchronized (queue) {
      queue.add(handler);
      queue.notify();
    }
  }

  static void loop() {
    while (true) {
      synchronized (queue) {
        while (queue.isEmpty()) {
          try {
            queue.wait();
          } catch (InterruptedException e) {}
        }
        for (Handler task: queue) {
          task.run();
        }
        queue.clear();
      }
    }
  }
}
