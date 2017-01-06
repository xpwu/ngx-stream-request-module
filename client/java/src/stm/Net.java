package stm;

/**
 *
 * Created by xpwu on 2016/11/28.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.*;
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
    ip_ = ip;
    ssl_ = false;
    if (ip.contains("ssl://")) {
      ssl_ = true;
      ip_ = ip.substring("ssl://".length());
    }
    port_ = port;
    socket_ = new Socket();
    inputTimer_ = new Timer();
    outputTimer_ = new Timer();
    config_ = new Config();
    ca_ = null;
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

  public void setTrustX509Certificate(X509Certificate ca) {ca_ = ca;}

  void open() {
    postTask(new Task() {
      @Override
      public void run() {
        if (status_ != Status.Closed) {
          return;
        }
        final int flag = ++socketFlag_;
        status_ = Status.Connecting;
        new Thread() {
          public void run(){
            do{
              try {
                socket_ = new Socket();
                socket_.connect(new InetSocketAddress(ip_, port_), config_.connectTimeout_ms);
                if (!ssl_) {
                  break;
                }

                SSLHandshakeException exception = null;
                SSLContext context = SSLContext.getInstance("SSL");
                context.init(null, null, null);
                SSLSocketFactory factory = context.getSocketFactory();
                SSLSocket socket = (SSLSocket)factory.createSocket(socket_, ip_, port_, true);
                try {
                  socket.startHandshake();
                } catch (SSLHandshakeException e) {
                  exception = e;
                }

                if (exception == null && ca_ == null) {
                  socket_ = socket;
                  break;
                }

                exception = null;
                socket_ = new Socket();
                socket_.connect(new InetSocketAddress(ip_, port_), config_.connectTimeout_ms);
                X509TrustManager x509m = new X509TrustManager() {
                  @Override
                  public X509Certificate[] getAcceptedIssuers() {
                    return null;
                  }

                  @Override
                  public void checkServerTrusted(X509Certificate[] chain,
                                                 String authType) throws CertificateException {
                    if (chain == null || chain.length == 0) {
                      throw new IllegalArgumentException("null or zero-length certificate chain");
                    }

                    if (authType == null || authType.length() == 0) {
                      throw new IllegalArgumentException("null or zero-length authentication type");
                    }

                    if (!chain[0].getSubjectX500Principal().getName().contains(ip_)) {
                      throw new CertificateException("Certificate not trusted");
                    }

                    int i = 1;
                    for (; i < chain.length; ++i) {
                      try {
                        chain[i-1].verify(chain[i].getPublicKey());
                      }
                      catch(Exception e){
                        throw new CertificateException("Certificate not trusted",e);
                      }
                      if (!chain[i-1].getIssuerX500Principal().equals(
                        chain[i].getSubjectX500Principal())) {
                        throw new CertificateException("Certificate not trusted");
                      }
                    }
                    try {// ca_ must be set
                      chain[i-1].verify(ca_.getPublicKey());
                    }
                    catch(Exception e){
                      throw new CertificateException("Certificate not trusted",e);
                    }
                    if (!chain[i-1].getIssuerX500Principal().equals(
                      ca_.getSubjectX500Principal())) {
                      throw new CertificateException("Certificate not trusted");
                    }

                    //If we end here certificate is trusted. Check if it has expired.
                    for (X509Certificate aChain : chain) {
                      try {
                        aChain.checkValidity();
                      } catch (Exception e) {
                        throw new CertificateException("Certificate not trusted. It has expired", e);
                      }
                    }
                  }
                  @Override
                  public void checkClientTrusted(X509Certificate[] chain,
                                                 String authType) throws CertificateException {
                  }
                };
                context.init(null, new TrustManager[]{x509m}, null);
                factory = context.getSocketFactory();
                socket = (SSLSocket)factory.createSocket(socket_, ip_, port_, true);
                try {
                  socket.startHandshake();
                } catch (SSLHandshakeException e) {
                  exception = e;
                }

                if (exception != null) {
                  final SSLHandshakeException e = exception;
                  postTask(new Task() {
                    @Override
                    public void run() {
                      closeAndOnClose(flag, e.toString());
                    }
                  });
                  return;
                }

                socket_ = socket;

              } catch (final KeyManagementException | IOException | NoSuchAlgorithmException e) {
                postTask(new Task() {
                  @Override
                  public void run() {
                    closeAndOnClose(flag, e.toString());
                  }
                });
                return;
              }
            }while (false);

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
    len[0] = (byte) ((length & 0xff000000) >> 24);
    len[1] = (byte) ((length & 0xff0000) >> 16);
    len[2] = (byte) ((length & 0xff00) >> 8);
    len[3] = (byte) (length & 0xff);

    synchronized (sendData_) {
      sendData_.add(len);
      sendData_.add(content);
      sendData_.notify();
    }
  }

  private void inputHeartbeatTimer(final int flag) {
    inputTimer_.cancel();
    inputTimer_ = new Timer();
    inputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
        postTask(new Task() {
          @Override
          public void run() {
            closeAndOnClose(flag, "heartbeat timeout");
          }
        });
      }
    }, 2*config_.hearbeatTime_ms);
  }

  private void inputTranslationTimer(final int flag) {
    inputTimer_.cancel();
    inputTimer_ = new Timer();
    inputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
        postTask(new Task() {
          @Override
          public void run() {
            closeAndOnClose(flag, "receive data timeout");
          }
        });
      }
    }, config_.translatioin_ms);
  }

  private Runnable getInputRunnable() {
    final int flag = socketFlag_;
    final Socket socket = socket_;
    return new Runnable() {
      @Override
      public void run() {
        try {
          InputStream input = socket.getInputStream();
          inputHeartbeatTimer(flag);
          while (!inputThreadEnd_) {

            byte[] lengthB = new byte[4];
            int pos = 0;
            while (!inputThreadEnd_ && 4 - pos != 0) {
              int n = input.read(lengthB, pos, 4 - pos);
              inputTimer_.cancel();

              if (n < 0) {
                postTask(new Task() {
                  @Override
                  public void run() {
                    closeAndOnClose(flag, "inputstream read error, maybe connection closed by peer");
                  }
                });
                inputTimer_.cancel();
                return;
              }
              if (n == 0) {
                postTask(new Task() {
                  @Override
                  public void run() {
                    closeAndOnClose(flag, "inputstream closed by peer");
                  }
                });
                inputTimer_.cancel();
                return;
              }
              pos += n;
              inputTranslationTimer(flag);
            }

            pos = 0;
            long length = ((0xff & lengthB[0]) << 24)
              + ((0xff & lengthB[1]) << 16)
              + ((0xff & lengthB[2]) << 8)
              + ((0xff & lengthB[3]));
            if (length == 0) { // heartbeat
              inputHeartbeatTimer(flag);
              //            System.out.println("heartbeat");
              continue;
            }

            length -= 4;
            final byte[] data = new byte[(int) length];
            while (!inputThreadEnd_ && length - pos != 0) {
              int n = input.read(data, pos, (int) length - pos);
              inputTimer_.cancel();

              if (n < 0) {
                postTask(new Task() {
                  @Override
                  public void run() {
                    closeAndOnClose(flag, "inputstream read error, maybe connection closed by peer");
                  }
                });
                inputTimer_.cancel();
                return;
              }
              if (n == 0) {
                postTask(new Task() {
                  @Override
                  public void run() {
                    closeAndOnClose(flag, "inputstream closed by peer");
                  }
                });
                inputTimer_.cancel();
                return;
              }
              pos += n;
              inputTranslationTimer(flag);
            }

            inputTimer_.cancel();
            postTask(new Task() {
              @Override
              public void run() {
                delegate_.onMessage(data);
              }
            });
            inputHeartbeatTimer(flag);
          }
        } catch (final IOException e) {
          postTask(new Task() {
            @Override
            public void run() {
              closeAndOnClose(flag, e.toString());
            }
          });
        }
      }
    };
  };

  private void outputHeartbeatTimer() {
//    System.out.println("outputHeartbeatTimer");
    outputTimer_.cancel();
    outputTimer_ = new Timer();
    outputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
//        System.out.println("outputHeartbeatTimer schedule");
        synchronized (sendData_) {
          byte[] heart = new byte[4];
          for (int i = 0; i < 4; ++i) {
            heart[i] = 0;
          }
          sendData_.add(heart);
          sendData_.notify();
        }
      }
    }, config_.hearbeatTime_ms, config_.hearbeatTime_ms);
  }

  private void outputTranslationTimer(final int flag){
//    System.out.println("outputTranslationTimer");
    outputTimer_.cancel();
    outputTimer_ = new Timer();
    outputTimer_.schedule(new TimerTask() {
      @Override
      public void run() {
//        System.out.println("outputTranslationTimer schedule");
        postTask(new Task() {
          @Override
          public void run() {
            closeAndOnClose(flag, "send data timeout");
          }
        });
      }
    }, config_.translatioin_ms);
  }

  private Runnable getOutputRunnable () {
    final int flag = socketFlag_;
    final Socket socket = socket_;
    return new Runnable() {
      @Override
      public void run() {
        OutputStream output = null;
        try {
          output = socket.getOutputStream();
        } catch (final IOException e) {
          postTask(new Task() {
            @Override
            public void run() {
              closeAndOnClose(flag, e.toString());
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
            outputTranslationTimer(flag);
            output.write(data);
            output.flush();
            outputHeartbeatTimer();
          } catch (final IOException e) {
            postTask(new Task() {
              @Override
              public void run() {
                closeAndOnClose(flag, e.toString());
              }
            });
            outputTimer_.cancel();
            return;
          }
        }
      }
    };
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
    inputThread_ = new Thread(getInputRunnable());
    inputThread_.start();
    outputThreadEnd_ = false;
    outputThread_ = new Thread(getOutputRunnable());
    outputThread_.start();

    delegate_.onOpen();
  }

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

  private void closeAndOnClose(int flag, String error) {
    if (flag != socketFlag_) {
      return;
    }
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
  private Socket socket_;
  private Config config_;
  private Thread inputThread_;
  private volatile boolean inputThreadEnd_;
  private Thread outputThread_;
  private volatile boolean outputThreadEnd_;
  private Timer inputTimer_;
  private Timer outputTimer_;
  private String ip_;
  private int port_;
  private X509Certificate ca_;
  private boolean ssl_;
  /**
   * 因为是异步执行, 同一个socket 的closeAndOnClose()会在不同的流中存在多次执行,
   * 可能造成新的socket已经打开, 但之前的socket 的closeAndOnClose 还没有全部执行,
   * 会造成关闭错误的socket。两种解决方案: 1、每次重建本类的实例, 当事件循环的处理比较麻烦;
   * 2、使用flag, 每次执行close 时判断是否关闭了正确的socket
   */
  private int socketFlag_;
}
