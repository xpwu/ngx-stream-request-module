package stm;

/**
 *
 * Created by xpwu on 2016/11/28.
 */

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.*;

/**
 *
 *  lencontent protocol:
 *
 *  1, handshake protocol:
 *
 *        client ------------------ server
 *          |                          |
 *          |                          |
 *        ABCDEF (A^...^F = 0xff) --->  check(A^...^F == 0xff) -N--> over
 *          |                          |
 *          |                          |Y
 *          |                          |
 *         data      <-------->       data
 *
 *
 *  2, data protocol:
 *     length | content
 *      length: 4 bytes, net order; length=sizeof(content)+4; length=0 => heartbeat
 *
 */


class Net {
  static class Config {
    int connectTimeout_ms = 30*1000;
    int hearbeatTime_ms = 4*60*1000;
    int translatioin_ms = 10*1000;
  }
  static abstract class Task {
    public abstract void run();
  }

  interface AsyncEventHandler {
    public void onFire();
  }
  void setAsyncEventHandler (AsyncEventHandler event) {
    event_ = event;
  }
  void pump(){
    synchronized (taskQueue_) {
      if (taskQueue_.isEmpty()) {
        return;
      }
      ArrayList<Task> tasks = new ArrayList<>(taskQueue_.size());
      tasks.addAll(taskQueue_);
      for (Task task : tasks) {
        task.run();
        taskQueue_.remove(task);
      }
      // 这里不能调用 clear(), 因为在task.run执行的过程中, 可能会产生新的task加入taskQueue_
//      taskQueue_.clear();
    }
  }

  interface Delegate {
    public void onOpen();
    public void onClose(String reason);
    public void onMessage(byte[] data);
  }

  enum Status {
    Connecting,
    Open,
    Closed
  }

  Status status() {
    return this.status_;
  }

  Net(String ip, int port) {
    status_ = Status.Closed;
    address_ = new InetSocketAddress(ip, port);
    socket_ = new Socket();
    inputTimer_ = new Timer();
    outputTimer_ = new Timer();
    config_ = new Config();
  }

  @Override
  protected void finalize() throws Throwable {
    close();
    inputThreadEnd_ = true;
    outputThreadEnd_ = true;
    inputTimer_.cancel();
    outputTimer_.cancel();
    super.finalize();
  }

  void setDelegate(Delegate delegate) {
    this.delegate_ = delegate;
  }
  void setConfig(Config config) {
    config_ = config;
  }
  Config getConfig(){return config_;}

  void open() {
    postTask(new Task() {
      @Override
      public void run() {
        if (status_ != Status.Closed) {
          return;
        }
        status_ = Status.Connecting;
        new Thread() {
          public void run(){
            try {
              socket_ = new Socket();
              socket_.connect(address_, config_.connectTimeout_ms);
            } catch (final IOException e) {
              postTask(new Task() {
                @Override
                public void run() {
//                  close();
//                  onClose(e.toString());
                  closeAndOnClose(e.toString());
                }
              });
              return;
            }

            postTask(new Task() {
              @Override
              public void run() {
                if (status_ == Status.Connecting) {
                  onOpen();
                }
              }
            });
          }
        }.start();
      }
    });
  }

  void send(byte[] content) {
    byte[] len = new byte[4];
    int length= content.length + 4;
    len[0] = (byte) (length & 0xff000000);
    len[1] = (byte) (length & 0xff0000);
    len[2] = (byte) (length & 0xff00);
    len[3] = (byte) (length & 0xff);

    synchronized (sendData_) {
      sendData_.add(len);
      sendData_.add(content);
      sendData_.notify();
    }
  }

  private void inputHeartbeatTimer() {
    inputTimer_.cancel();
    inputTimer_ = new Timer();
    inputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
        postTask(new Task() {
          @Override
          public void run() {
//            close();
//            onClose("heartbeat timeout");
            closeAndOnClose("heartbeat timeout");
          }
        });
      }
    }, 2*config_.hearbeatTime_ms);
  }

  private void inputTranslationTimer() {
    inputTimer_.cancel();
    inputTimer_ = new Timer();
    inputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
        postTask(new Task() {
          @Override
          public void run() {
//            close();
//            onClose("receive data timeout");
            closeAndOnClose("receive data timeout");
          }
        });
      }
    }, config_.translatioin_ms);
  }

  private Runnable inputRunnable = new Runnable() {
    @Override
    public void run() {
      try {
        InputStream input = socket_.getInputStream();
        inputHeartbeatTimer();
        while (!inputThreadEnd_) {

          byte[] lengthB = new byte[4];
          int pos = 0;
          while (!inputThreadEnd_ && 4-pos != 0) {
            int n = input.read(lengthB, pos, 4-pos);
            inputTimer_.cancel();

            if (n < 0) {
              postTask(new Task() {
                @Override
                public void run() {
//                  close();
//                  onClose("inputstream read error, maybe connection closed by peer");
                  closeAndOnClose("inputstream read error, maybe connection closed by peer");
                }
              });
              inputTimer_.cancel();
              return;
            }
            if (n == 0) {
              postTask(new Task() {
                @Override
                public void run() {
//                  close();
//                  onClose("inputstream closed by peer");
                  closeAndOnClose("inputstream closed by peer");
                }
              });
              inputTimer_.cancel();
              return;
            }
            pos += n;
            inputTranslationTimer();
          }

          pos = 0;
          long length = ((0xff&lengthB[0])<<24)
            + ((0xff&lengthB[1])<<16)
            + ((0xff&lengthB[2])<<8)
            + ((0xff&lengthB[3]));
          if (length == 0) { // heartbeat
            inputHeartbeatTimer();
//            System.out.println("heartbeat");
            continue;
          }

          length -= 4;
          final byte[] data = new byte[(int)length];
          while (!inputThreadEnd_ && length-pos != 0) {
            int n = input.read(data, pos, (int)length-pos);
            inputTimer_.cancel();

            if (n < 0) {
              postTask(new Task() {
                @Override
                public void run() {
//                  close();
//                  onClose("inputstream read error, maybe connection closed by peer");
                  closeAndOnClose("inputstream read error, maybe connection closed by peer");
                }
              });
              inputTimer_.cancel();
              return;
            }
            if (n == 0) {
              postTask(new Task() {
                @Override
                public void run() {
//                  close();
//                  onClose("inputstream closed by peer");
                  closeAndOnClose("inputstream closed by peer");
                }
              });
              inputTimer_.cancel();
              return;
            }
            pos += n;
            inputTranslationTimer();
          }

          inputTimer_.cancel();
          postTask(new Task() {
            @Override
            public void run() {
              delegate_.onMessage(data);
            }
          });
          inputHeartbeatTimer();
        }
      } catch (final IOException e){
        postTask(new Task() {
          @Override
          public void run() {
//            close();
//            onClose(e.toString());
            closeAndOnClose(e.toString());
          }
        });
      }
    }
  };

  private void outputHeartbeatTimer() {
    outputTimer_.cancel();
    outputTimer_ = new Timer();
    outputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
        synchronized (sendData_) {
          byte[] heart = new byte[4];
          for (int i = 0; i < 4; ++i) {
            heart[i] = 0;
          }
          sendData_.add(heart);
          sendData_.notify();
        }
        outputHeartbeatTimer();
      }
    }, config_.hearbeatTime_ms);
  }

  private void outputTranslationTimer(){
    outputTimer_.cancel();
    outputTimer_ = new Timer();
    outputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
        postTask(new Task() {
          @Override
          public void run() {
//            close();
//            onClose("send data timeout");
            closeAndOnClose("send data timeout");
          }
        });
      }
    }, config_.translatioin_ms);
  }

  private Runnable outputRunnable = new Runnable() {
    @Override
    public void run() {
      OutputStream output = null;
      try {
        output = socket_.getOutputStream();
      } catch (final IOException e) {
        postTask(new Task() {
          @Override
          public void run() {
//            close();
//            onClose(e.toString());
            closeAndOnClose(e.toString());
          }
        });
        return;
      }
      outputHeartbeatTimer();
      while (!outputThreadEnd_) {
        byte[] data = getSendData();
        if (data == null) {
          break;
        }
        try {
          outputTranslationTimer();
          output.write(data);
          outputHeartbeatTimer();
        } catch (final IOException e) {
          postTask(new Task() {
            @Override
            public void run() {
//              close();
//              onClose(e.toString());
              closeAndOnClose(e.toString());
            }
          });
          outputTimer_.cancel();
          return;
        }
      }
    }
  };

  private void onOpen(){ // main thread
    status_ = Status.Open;
    // handshake
    byte[] handshake = new byte[6];
    handshake[5] = (byte) 0xff;
    for (int i = 0; i < 5; ++i) {
      handshake[5] ^= (byte)handshake[i];
    }

    synchronized (sendData_) {
      sendData_.add(handshake);
      sendData_.notify();
    }

    inputThreadEnd_ = false;
    inputThread_ = new Thread(inputRunnable);
    inputThread_.start();
    outputThreadEnd_ = false;
    outputThread_ = new Thread(outputRunnable);
    outputThread_.start();

    delegate_.onOpen();
  }

//  private void onClose(String error) {
//    if (status_ == Status.Closed) {
//      return;
//    }
//    delegate_.onClose(error);
//  }

  private void close() {
    if (status_ == Status.Closed) {
      return;
    }

    status_ = Status.Closed;
    try {
      socket_.close();
    } catch (IOException e) {}

    inputThreadEnd_ = true;
    outputThreadEnd_ = true;
    if (inputThread_ != null) {
      inputThread_.interrupt();
    }
    if (outputThread_ != null) {
      outputThread_.interrupt();
    }

    reset();
  }

  private void closeAndOnClose(String error) {
    close();
    delegate_.onClose(error);
  }

  private void reset() {
    sendData_.clear();
    status_ = Status.Closed;

    inputThread_ = null;
    outputThread_ = null;
  }

  private byte[] getSendData() {
    synchronized (sendData_) {
      while (sendData_.isEmpty()) {
        try {
          sendData_.wait();
        } catch (InterruptedException e) {
          return null;
        }
      }
      return sendData_.remove(0);
    }
  }

  void postTask(Task task) {
    synchronized (taskQueue_) {
      taskQueue_.add(task);
    }
    fireAsyncEvent();
  }
  private void fireAsyncEvent() {
    if (event_ == null) {
      return;
    }
    event_.onFire();
  }

  private Status status_;
  private Delegate delegate_;
  private final List<Task> taskQueue_ = new LinkedList<>(); // current thread queue
  private AsyncEventHandler event_;
  private final List<byte[]> sendData_ = new LinkedList<>(); // send thread queue
  private SocketAddress address_;
  private Socket socket_;
  private Config config_;
  private Thread inputThread_;
  private volatile boolean inputThreadEnd_;
  private Thread outputThread_;
  private volatile boolean outputThreadEnd_;
  private Timer inputTimer_;
  private Timer outputTimer_;
}
