# ngx-stream-request-module

## 目录
[**简介**](#abstract)  
[**名词解释**](#define)  
[**模块**](#module)  
>[ngx-stream-request-module](#ngx-stream-request-module)  
[ngx-stream-request-websocket-module](#ngx-stream-request-websocket-module)  
[ngx-stream-request-lencontent-module](#ngx-stream-request-lencontent-module)  
[ngx-stream-request-push-module](#ngx-stream-request-push-module)  
[ngx-stream-request-http-proxy-module](#ngx-stream-request-http-proxy-module)  
[ngx-stream-request-fake-http-module](#ngx-stream-request-fake-http-module)  
[ngx-stream-request-push-data-module](#ngx-stream-request-push-data-module)  
[ngx-stream-request-push-close-session-module](#ngx-stream-request-push-close-session-module)  
[ngx-stream-request-set-module](#ngx-stream-request-set-module)  
[配置demo](#demo)  

[**客户端**](#client)  
 > [接口说明](#sdk)  
  [各端的特殊情况](#sdk-spe)  
  
[**Push**](#push)  
[**ssl支持**](#ssl)  


## <a name="abstract"></a>简介

基于ngx-stream-module 实现长连接的处理，把长连接数据按照使用的协议转切分为请求(request)，与后端服务器使用短连接通讯，完全兼容后端http协议。后端服务器使用推送协议可以很方便的把数据推送到客户端。

## <a name="define"></a>名词解释

* 会话(session): 客户端与服务器建立连接后就形成一次会话, 一次连接对应一次会话, 不同的连接对应不同的会话. 因此对于服务器来说, 一个会话能唯一标示一个客户端。
* 请求(request): 在长连接上按照协议规范传输的请求包，请求是ngx-stream-request-module处理的基本数据包。
* 参数(var): 参数分基于request的参数和基于session的参数，stream原有模块的参数都是基于session的参数，再ngx-stream-request-xxx-module中仍然可以使用。基于request的参数会先从当前处理的request中获取，如果没有找到参数值，会在session中查找；基于session的参数被所有request共享。

## <a name="module"></a>模块

基于 **nginx 1.12** 版本实现，不兼容1.12之前的版本。

### <a name="ngx-stream-request-module"></a>ngx-stream-request-module
*此模块是基础模块，使用request-xxx其他任何模块时，必须首先添加此模块*


* 命令: 此模块提供如下配置命令

    |    命令           |     参数        | 说明        |默认值|
    |------------------|-----------------|------------|-----|
    | `request_variables_hash_max_size` | 一个|设置request变量的hash表大小|1024|
    | `request_variables_hash_bucket_size` |一个|设置request变量的hash bucket大小|64|
    |以下为配置upstream的协议|
    |`request_proxy_connect_timeout`| 一个(ms) |连接后端服务器的超时时间|60000ms|
    |`request_proxy_next_upstream`| 一个(on/off) |是否自动连接下一个后端服务器|on|
    |`request_proxy_next_upstream_tries`| 一个|寻找下一个后端服务器的次数|0|
    |`request_proxy_next_upstream_timeout`|一个(ms)|查找下一个服务的超时时间|0|
    |`request_send_to_proxy_timeout`|一个(ms)|发送数据给后端的最长时间|5000|
    |`request_receive_from_proxy_timeout`|一个(ms)|接收后端数据的最长间隔时间|5000|
    |`request_proxy_response_timeout`|一个(ms)|后端服务器响应的最长时间|10000|
    |以下为配置客户端数据传输的参数|||
    |`request_receive_from_client_timeout`|一个(ms)|从客户端接收数据的最长等待时间|10000|
    |`request_send_to_client_timeout`|一个(ms)|发送数据到客户端的最长超时时间|10000|
    |`client_heartbeat`|一个(ms)|客户端的心跳时间|4 * 60 * 1000|
    
### <a name="ngx-stream-request-websocket-module"></a>ngx-stream-request-websocket-module
* websocket协议模块，分析websocket协议，从长连接数据流中解析出请求，此模块不对websocket的应用层数据做处理；同时把数据按照websocket的协议进行封装，回传给客户端。
* 命令

|命令|参数|说明|默认值|
|---|---|----|-----|
|websocket_protocol|无|表示此server使用websocket协议||
|ws_access_origins|一个|接收的origin地址，可以多次配置，如果允许所有，可以配置为all| all |
|ws_handshake_timeout|一个(ms)|发送握手数据的最长超时|5000|

### <a name="ngx-stream-request-lencontent-module"></a>ngx-stream-request-lencontent-module
* lencontent协议模块，协议格式如下:

```
 lencontent protocol:
 
 1, handshake protocol:
 
       client ------------------ server
          |                          |
          |                          |
       ABCDEF (A^...^F = 0xff) --->  check(A^...^F == 0xff) -N--> over
          |                          |
          |                          |Y
          |                          |
        data      <-------->       data


   2, data protocol:
     1) length | content
       length: 4 bytes, net order; length=sizeof(content)+4; length=0 => heartbeat
 
```
content的数据格式由sub protocol确定

* 命令：

|命令|参数|说明|默认值|
|---|---|----|-----|
|lencontent_protocol|无|表示此server使用lencontent协议||
|lenc_handshake_timeout|一个(ms)|握手数据的最长超时时间|5000|

### <a name="ngx-stream-request-push-module"></a>ngx-stream-request-push-module
* push 协议模块，主要用于后端服务器向nginx推送数据。协议格式如下:

```
  request:
   sequece | token | subprotocol | len | <data>
     sizeof(sequece) = 4. net order
     sizeof(token) = 32 . hex
     sizeof(subprotocol) = 1.
     sizeof(len) = 4. len = sizof(data) net order
     data: subprotocol request data
 
  response:
   sequece | state | len | <data>
     sizeof(sequece) = 4. net order
     sizeof(state) = 1.
               state = 0: success; 1: hostname error
                ; 2: token not exist; 3: server intelnal error
     sizeof(len) = 4. len = sizeof(data) net order
     data: subprotocol response data
```

* 命令：

|命令|参数|说明|默认值|
|---|---|----|-----|
|push_protocol|无|表示此server使用push协议||
|push_receive_timeout|一个(ms)|数据接收的超时时间|5000|
|push_shared_memory_size|一个(K/M)|共享内存大小|默认32个页面大小|

* 变量：push modul提供如下变量

|变量|说明|
|---|---|
|sessiontoken|session的唯一标示符，一个sessiontoken对应于一个session，推送时需要使用此变量|

### <a name="ngx-stream-request-http-proxy-module"></a>ngx-stream-request-http-proxy-module

* http 代理模块，把收到的每一个请求使用http的协议格式发送给后端服务器
* 命令：

|命令|参数|说明|默认值|
|---|---|----|-----|
|http_proxy_pass|一个|指定代理的地址，url格式，支持变量|无|
|http_proxy_add_header|两个|添加http代理的header，支持变量||
|http_proxy_last_uri|一个|如果设置此值，当长连接断开时，会发送此uri给后端服务器，支持变量||
|http_proxy_resp_headers_hash_size|一个|设置http proxy 响应的头部hash池|11|

* 变量：

|变量|说明|
|---|---|
|http_proxy_ |前缀变量，http proxy返回的头部均可用此变量方式获取，基于session的变量，后面请求返回的头部会覆盖前序请求相同field的头部。但是如下头部不支持此变量：Date, Server, Connection, Content-Type, Content-Length, Transfer-Encoding|

* POST GET 方法的说明

1.	如果body参数不为空，后端的http请求会使用POST协议，如果为空，则使用GET协议。
2.	如果body和header都为空，一样会发起http请求，使用GET协议。
3.	GET协议如何加参数？直接在代理地址中按照http的方式设置即可

### <a name="ngx-stream-request-fake-http-module"></a>ngx-stream-request-fake-http-module

* fake http 子协议，可用于其他任何协议的应用层数据解析，协议格式如下：

```
content protocol:
     request ---
       reqid | headers | header-end-flag | data
         reqid: 4 bytes, net order;
         headers: < key-len | key | value-len | value > ... ;  [optional]
           key-len: 1 byte,  key-len = sizeof(key);
           value-len: 1 byte, value-len = sizeof(value);
         header-end-flag: 1 byte, === 0;                      
         data:       [optional]
 
     response ---
       reqid | status | data
         reqid: 4 bytes, net order;
         status: 1 byte, 0---success, 1---failed
         data: if status==success, data=<app data>    [optional]
               if status==failed, data=<error reason>
 
 
     reqid = 1: server push to client
     
```

* 命令：

|命令|参数|说明|默认值|
|---|---|----|-----|
|fake_http_subprotocol|无|使用fake http 子协议||
|fake_http_log_format|一个|fake http 的log格式，可以使用变量||

* 变量：fake http提供如下变量

|变量|说明|
|---|---|
|fhttp_reqid|基于请求的变量，表示此请求中reqid的值|
|fhttp_ |前缀变量，协议header中的key均可使用此变量方式获取，比如 fhttp_api|

### <a name="ngx-stream-request-push-data-module"></a>ngx-stream-request-push-data-module

* push 协议的一种子协议，用于向客户端推送数据，push_protocol中的data全部推送给客户端
* 命令：

|命令|参数|说明|默认值|
|---|---|----|-----|
|push_data_subprotocol|一个|使用push data子协议，参数表示子协议号，参见push_protocol中的subprotocol字段|0|

### <a name="ngx-stream-request-push-close-session-module"></a>ngx-stream-request-push-close-session-module

* push 协议的一种子协议，用于关闭sessiontoken对应的长连接，无data
* 命令

|命令|参数|说明|默认值|
|---|---|----|-----|
|push_close_session_subprotocol|一个|使用push close session子协议，参数表示子协议号，参见push_protocol中的subprotocol字段|1|


### <a name="ngx-stream-request-set-module"></a>ngx-stream-request-set-module

* 设置变量的值，值也可以是一个变量，值变量可以是基于request的
* 命令

|命令|参数|说明|默认值|
|---|---|----|-----|
|rset|两个|设置变量值，比如rset $var $value||

### <a name="demo"></a>配置demo

```
stream {
  error_log  logs/stream.log info;
  
  server {
    listen 7999;
    push_protocol;
    push_data_subprotocol 0;
    push_close_session_subprotocol 1;
  } 
  
  server {
    listen 8000;
    lencontent_protocol;
    fake_http_subprotocol;
    http_proxy_pass 127.0.0.1:10000/$fhttp_api;
    http_proxy_last_uri /CloseSession;
    http_proxy_add_header PushUrl 127.0.0.1:7999/$sessiontoken;
  } 
  
  server {
    listen 8001;
    websocket_protocol;
    fake_http_subprotocol;
    http_proxy_pass 127.0.0.1:10000/$fhttp_api;
    http_proxy_last_uri /CloseSession;
    http_proxy_add_header PushUrl 127.0.0.1:7999/$sessiontoken;
  } 
}
```
如上配置了3个服务器，一个用于接收push，一个用于websocket的解析，一个用于lencontent的解析，websocket与lencontent都是使用fake http子协议，并代理给127.0.0.1:10000服务器。当session关闭时，发送/CloseSession请求给后端http服务器。

## <a name="client"></a>客户端

### <a name="sdk"></a>接口说明

客户端SDK，支持ios android web 小程序。其中web与小程序使用websocket，ios android 使用lencontent协议，都是使用fake http 子协议。客户端主要接口如下：

1.  setConfig... 配置客户端的时间参数, 主要配置连接超时(默认为30s), 传输超时(默认10s), 心跳（默认4 * 60s); 如果使用默认值，不需调用此接口。
2.  setConnect... 设置连接参数。onSuccess 为连接成功的回调接口；onFailed 为连接出现错误的回调接口，一旦该接口被调用会话将结束，错误描述在onFailed中返回。此接口为必须调用。调用此接口后仅是设置了参数，不会发起网络连接等操作。
3.  addRequest... 添加请求。onSuccess 为请求成功的回调接口，响应数据通过onSuccess返回；onFailed 为请求失败的回调接口，错误描述在onFailed中返回。onComplete 为请求完成的接口，无论失败还是成功，此接口都会调用。body 为请求的数据，对应于Http 的post数据；headers 为头信息，是string类型的key => value对，key在服务器端可以当变量使用，对于此请求会覆盖session的同名变量，但不会更新session中此变量的值，参见变量部分的具体说明。
4.	 onPush = ...  设置回调的响应函数，服务器push的消息通过此回调返回。

**特别说明：**

1. 在返回的数据中，不会返回http响应的头信息，如果客户端需要用到头中的信息，请在响应数据中返回；服务器端可以利用http的头信息更新session变量；
2. 对于body 与 响应的数据格式不做规定，由客户端与服务器处理逻辑自行协商；
3. 调用此接口后，自动进行网络连接状态判断，并作出连接/重连等操作；
4. 只要请求被添加，就一定会有回调产生，处理结束无论成功与否都会调用onComplete，如果成功onSuccess会被调用，如果失败，onFailed会被调用，出现的任何错误都会通过此接口中的onFailed返回；
5. 一般情况下，响应都是异步回调，只有必须要的参数没有设置的情况下(比如网络参数)，才会同步回调onComplete与onFailed，在正式使用场景中不应出现必须要的参数没有设置的情况，因此，在正式环境中，所有的回调都是异步回调。



**Q&A**

1.	Q：为什么没有主动连接接口？  
	A：目前设计希望调用方更多的关注Request，而不是Connection，一个Request与以前一个http的短连接请求类似，达到调用习惯的一致性。如果多加一个接口，可能会增加调用的不清晰性。
2.	Q：怎么知道连续连接失败的次数？  
	A：setConnect... 中onFailed连续调用的次数即可得到连续失败的次数。可以实现多次失败后的处理策略，比如客户端的负载均衡等。
4.	Q：addRequest中的请求是否按照添加的顺序依次执行？  
	A：不是。request之间没有时间的先后顺序关系，独立请求，独立响应。
5.	Q：使用的什么编码？  
	A：body和响应中任何编码都可以，由client上层和后台逻辑自行商议，headers 只能使用ascii编码。

### <a name="sdk-spe"></a>各端的特殊情况

* **js/小程序**

1. 底层使用websocket实现，对于不支持websocket的js端，此SDK无法运行
2.	此SDK需要第三方库stringview支持。[StringView](https://developer.mozilla.org/en-US/Add-ons/Code_snippets/StringView) 或者 [StringView github](https://github.com/madmurphy/stringview.js)
3.	接口中的参数如果无需传递，可以设置为null；
4.	setConfig中只需设置连接超时时间，其他配置参数由websocket自己设置
5.	body 参数可以是string类型或者ArrayBuffer类型，onSuccess 返回的类型为ArrayBuffer类型，ArrayBuffer 转换为string 可以使用StringView，见例子的使用。
6.  增加json接口，输入和返回都是json
7.  增加了onPushJson 接口，会返回json格式串，与onPush接口设置一个即可。数据必须是可以JSON反序列化，否则会报错

* **ios**

1.	ios SDK实现了多个重载版本，可根据情况灵活调用。对于不感兴趣的参数，可以设置为nil
2.	如果是JSON，可以使用NSJSONSerialization或者其他第三方库进行转换。
3. 如果编译出现链接问题，可以把调用文件改为.mm试试

* **java**

1.	java比其他客户端SDK多一个接口pump和一个回调设置接口setAsyncEventHandler，这两个接口是必须接口。为了使用纯java实现，无法使用android系统库或者其他系统中的事件机制，所以提供了这两个接口让调用方实现。仅需在asyncEventHandler 中的onFire 回调中向调用addRequest的线程post一个事件，事件的处理逻辑就是调用pump接口。asyncEventHandler 中的onFire 回调线程具有不确定性，由于整个Client都不是线程安全的，为了保证线程安全，需要调用pump接口的线程与调用addRequest的线程是同一个线程。在demo中模拟了一个简单的事件循环机制，列出了setAsyncEventHandler与pump的调用范例。
2.	不关注的参数可以传入null。


## <a name="push"></a>Push

后端服务器可以根据push协议实现自己后端语言的sdk，这里实现了php语言的push sdk, 支持 push data 与push close session两种子协议, 具体使用见demo. 

## <a name="ssl"></a>ssl支持

1.  服务器编译：需要另外加入编译参数 --with-stream_ssl_module
2.  服务器配置：使用stream配置ssl的方法配置，常用命令为：ssl_certificate  ssl_certificate_key ssl_password_file
3.  js 使用ssl: 由原来的ws:// 变更为 wss://
4.  ios/android 使用ssl: 在host前面加入 ssl://

