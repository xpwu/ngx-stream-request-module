# ngx-stream-request-module



##简介
实现客户端到服务器的长连接通信, 客户端与服务器之间仅需一条长连接就可实现客户端到服务器get数据,以及服务器向客户端push数据. 无需更改服务器逻辑即可实现现有的http短连接方式升级到长连接. 支持 ios android web，也支持ssl连接

##名词解释
* 会话(session): 客户端与服务器建立连接后就形成一次会话, 一次连接对应一次会话, 不同的连接对应不同的会话. 因此对于服务器来书, 一个会话能唯一标示一个客户端。服务器端可以对会话设置变量，会话是有状态的，可以保留一些参数在会话中，而不用重复传递这些数据。
* 请求(request): 客户端向服务器发起的一次数据交换. 请求是在会话中传输, 一个会话可以传输若干请求, 同一个会话的所有请求可以共享该会话已有的数据(见服务器部分). 请求在会话中的传输是异步的, 下一个请求的传输不需要等待上一个请求结束后再传输, 可以简单认为请求是在会话上并行传输(有一种情况例外, 见客户端部分). 客户端的一个请求, 经过长连接服务器后转为向后端服务器的一个短连接请求. 请求共享请求所在会话的变量, 也可以在客户端增加变量, 也可以覆盖会话的变量, 可以参见后面变量说明专栏

##服务器
目前仅支持nginx 1.10.1 实现原理为: 把长连接按照请求为单位切分为短连接, 发给上游的http服务器

* 编译: 支持静态编译和动态编译, 假如stream_module的路径为/path/to/stream_module, 使用 --add-module=/path/to/stream_module 参数即可把模块静态编入nginx 中, 具体可以参加nginx的三方模块编译说明文档.使用--add-dynamic-module=/path/to/stream_module生成动态库ngx_stream_request_module.so
* 配置: 此模块属于stream模块, 因此需要在stream 部分配置, stream 原有的server listen error_log等命令继续使用.

    |    命令             |     参数           | 说明        |
    |:------------------:|:-----------------:|:------------|
    | session_request    | 无                 | stream 切入session_request模式, 必须配置|
    |以下3个配置为协议配置, 一个server 必须配置其中一种协议|||
    |lencontent_protocol | 无                 | 主要用于ios与android|
    |websocket_protocol  | 无                 | 主要用于web|
    |push_protocol       | 无                 |主要用于push|
    |以下为session参数的设置，支持main和server级别的配置，<br>对同一变量名的多次配置，server级别会覆盖main级别的配置，<br>后配置的会覆盖先配置的|||
    |set|两个参数|第一个参数为session变量, 第二个参数为值. <br>第一个参数必须以$开头. <br>例如: set $name xpwu, 表示把session的name变量设置为xpwu.<br> 此设置对连接到此服务的任何session都进行了设置|
    |set_if_empty|两个参数|参数意义与set相同. 此命令在session的变量为空时, 才设置变量的值, 实际中使用较少|
    | 以下为使用websocket协议的服务设置|||
    |ws_access_origins|一个参数|设置允许通信的origin连接, 默认值为全部都允许通信.<br>重复使用该命令, 可以加入多个允许通信的连接.<br> 设置为'all', 表示允许全部连接通信, 与默认值的表现一致|
    |以下为长连接转为http短连接的代理设置，支持main和server级别的配置，<br>对同一变量名的多次配置，server级别会覆盖main级别的配置，<br>后配置的会覆盖先配置的|||
    | http_proxy_pass |一个参数|设置http服务器地址, 支持stream的负载均衡设置|
    |http_proxy_set_uri|一个参数|设置http协议中的uri信息, 参数可以为字符串常量.<br>如果是$开头,则表示为取变量的值.<br>默认值的设置参见http_proxy_set_header_if_empty|
    |http_proxy_set_header|两个参数|设置http协议中的头信息, 第一个参数为头域的名字, <br>第二个参数为头域的值, 可以是常量, 也可以是变量|
    |http_proxy_set_header_if_empty|两个参数|设置方式同http_proxy_set_header. <br>区别是, 此项的设置只有在头域值为空时才有效. <br>这里的空包括没有设置过该头域以及该头域值为空串两种情况. <br> 使用 http_proxy_set_header_if_empty URI xxx 可以设置uri的默认值|
    |http_proxy_set_session|两个参数|通过http响应的头域设置或者更新session变量的值.<br>两个参数都为变量, 第一个参数为session变量, 第二个参数为http响应的头域名|
    |http_proxy_set_session_if_empty|两个参数|使用同上. 该设置仅在session变量不存在时才起作用, <br> 如果session变量存在, 但值为空串, 该项仍不起作用|
    |其他设置|||
    |request_send_to_proxy_timeout|一个参数, 默认单位s，可加后缀|设置向http服务器发送数据中的最长等待时间, <br>如果时间超过此值, 认为与http服务的通信异常, <br>默认值为5000|
    |request_receive_from_proxy_timeout|一个参数, 默认单位s，可加后缀|设置接收http服务器数据的最长等待时间, <br>如果时间超过此值, 认为与http服务的通信异常, <br>默认值为5000|
    |request_proxy_response_timeout|一个参数, 默认单位s，可加后缀|设置接收http服务器响应的最长等待时间, <br>如果时间超过此值, 认为响应失败, <br>默认值为10000|
    |request_proxy_connect_timeout|一个参数, 默认单位s，可加后缀|连接代理的超时时间, <br>默认值为60000|
    |client_handshake_timeout|一个参数, 默认单位s，可加后缀| 服务器收到客户端握手信号的最长等待时间, <br>超过此时间, 认为是无效连接, 不能建立会话, 自动断开连接, <br>默认值为30000|
    |request_receive_from_client_timeout|一个参数, 默认单位s，可加后缀|接收客户端相邻两包数据的最长等待时间, <br>超过此值, 认为连接不通畅, 连接断开, 会话结束, <br>默认值为10000|
    |request_send_to_client_timeout|一个参数, 默认单位s，可加后缀|向客户端发送相邻两包数据的最长等待时间, <br>超过此值, 认为连接不通畅, 连接断开, 会话结束, <br>默认值为10000|
    |client_heartbeat|一个参数, 默认单位s，可加后缀|设置与客户端的心跳时间, <br>服务器在2 * client_heartbeat的时间至少要收到一个客户端发来的心跳包, <br>服务器在client_heartbeat的时间间隔内会向客户端发送一个心跳包<br>超过此值, 认为连接已断开, 会话已结束, <br>默认值为4 * 6000|
    |request_failed_log_to_client|一个参数, on/off|是否把服务器的错误日志发送给客户端|
    | |||
    |push_shared_memory_size|一个参数, 可用K/M后缀| 设置push模块的共享内存大小, 默认为32个页面单位|
    
    
* 配置示例

>	1.  push server
    server {
        listen 10002;
        session_request;
        push_protocol;
    }
    
>	2.  websocket
    server {
        listen 10001;
        session_request;
        request_failed_log_to_client on;
        websocket_protocol;
        http_proxy_pass 127.0.0.1:10000;
        http_proxy_set_uri /myself_practice/php/test.php;
        http_proxy_set_header Host $host;
        http_proxy_set_header SessionToken $session_token;
        http_proxy_set_session $test $Test;
        set $host localhost;
    }
    
>	3.  lencontent
    server {
		listen 10003;
		session_request;
		request_failed_log_to_client on;
		lencontent_protocol;
		http_proxy_pass 127.0.0.1:10000;
		http_proxy_set_uri /myself_practice/php/test.php;
		http_proxy_set_header Host $host;
		http_proxy_set_header SessionToken $session_token;
		http_proxy_set_session $test $Test;	
		set $host localhost;
	}
	
##客户端
客户端主要有5个接口, 调用其中两个即可实现和服务器的通信, 调用简单.

1.  setConfig... 配置客户端的时间参数, 主要配置连接超时(默认为30s), 传输超时(默认10s), 心跳（默认4 * 60s); 如果使用默认值，不需调用此接口。
2.  setConnect... 设置连接参数。onSuccess 为连接成功的回调接口；onFailed 为连接出现错误的回调接口，一旦该接口被调用会话将结束，错误描述在onFailed中返回。此接口为必须调用。调用此接口后仅是设置了参数，不会发起网络连接等操作。
3.  addRequest... 添加请求。onSuccess 为请求成功的回调接口，响应数据通过onSuccess返回；onFailed 为请求失败的回调接口，错误描述在onFailed中返回。onComplete 为请求完成的接口，无论失败还是成功，此接口都会调用。body 为请求的数据，对应于Http 的post数据；headers 为头信息，是string类型的key => value对，key在服务器端可以当变量使用，对于此请求会覆盖session的同名变量，但不会更新session中此变量的值，参见变量部分的具体说明。
>   **特别说明：**
>   1、在返回的数据中，不会返回http响应的头信息，如果客户端需要用到头中的信息，请在响应数据中返回；服务器端可以利用http的头信息更新session变量；
>   2、对于body 与 响应的数据格式不做规定，由客户端与服务器处理逻辑自行协商；
>   3、调用此接口后，自动进行网络连接状态判断，并作出连接/重连等操作；
>   4、只要请求被添加，就一定会有回调产生，处理结束无论成功与否都会调用onComplete，如果成功onSuccess会被调用，如果失败，onFailed会被调用，出现的任何错误都会通过此接口中的onFailed返回；
>   5、一般情况下，响应都是异步回调，只有必须要的参数没有设置的情况下(比如网络参数)，才会同步回调onComplete与onFailed，在正式使用场景中不应出现必须要的参数没有设置的情况，因此，在正式环境中，所有的回调都是异步回调。

4.  setBlockRequestOnConnected... 在一些应用中，每次连接成功时，都会先发起一个请求，在此请求返回后根据情况再判断是否需要发起其他请求，比如登录/鉴权等，此接口实现此需求。BlockRequest会在连接成功后自动发给服务器，响应接口通过回调返回。blockRequest对通过addRequest添加的请求的影响：如果blockRequest请求失败，通过addRequest添加的请求将不会发往服务器，并通过addRequest的onFailed返回错误说明（当然onComplete也会被回调，后续将不再作onComplete的回调说明）。如果blockRequest成功，但是在blockRequest的onSuccess回调中返回了false(NO)，对普通请求与blockRequest返回失败的情况一样。如果blockRequest成功且onSuccess回调中返回了true(YES)，会自动执行addRequest添加的请求。
5.	onPush = ...  设置回调的响应函数，服务器push的消息通过此回调返回。

**Q&A**
>	1.	Q：为什么没有主动连接接口？
>		A：目前设计希望调用方更多的关注Request，而不是Connection，一个Request与以前一个http的短连接请求类似，达到调用习惯的一致性。如果多加一个接口，可能会增加调用的不清晰性。
>	2.	Q：怎么知道连续连接失败的次数？
>		A：setConnect... 中onFailed连续调用的次数即可得到连续失败的次数。可以实现多次失败后的处理策略，比如客户端的负载均衡等。
>	3.	Q：如何实现每次请求都需要传递的参数，仅传递一次就可？
>		A：客户端通过blockRequest配合服务器的变量配置即可实现，看完后面的变量说明部分，应该能明白怎么配置。
>	4.	Q：addRequest中的请求是否按照添加的顺序依次执行？
>		A：不是。request之间没有时间的先后顺序关系，独立请求，独立响应。只有blockRequest与普通request有时间关系。
>	5.	Q：使用的什么编码？
>		A：body和响应中任何编码都可以，由client上层和后台逻辑自行商议，headers 只能使用ascii编码。

#### js的特别说明
1.	底层使用websocket实现，对于不支持websocket的js端，此SDK无法运行
2.	此SDK需要第三方库stringview支持。[StringView](https://developer.mozilla.org/en-US/Add-ons/Code_snippets/StringView) 或者 [StringView github](https://github.com/madmurphy/stringview.js)
3.	接口中的参数如果无需传递，可以设置为null；
4.	setConfig中只需设置连接超时时间，其他配置参数由websocket自己设置
5.	body 参数可以是string类型或者ArrayBuffer类型，onSuccess 返回的类型为ArrayBuffer类型，ArrayBuffer 转换为string 可以使用StringView，见例子的使用。
6.	blockRequest 的onSuccess 如果没有明确返回false，即认为返回了true。


#### ios的特别使用
1.	ios SDK实现了多个重载版本，可根据情况灵活调用。对于不感兴趣的参数，可以设置为nil
2.	如果是JSON，可以使用NSJSONSerialization或者其他第三方库进行转换。
3.  如果编译出现链接问题，可以把调用文件改为.mm试试


#### java的特别说明
1.	java比其他客户端SDK多一个接口pump和一个回调设置接口setAsyncEventHandler，这两个接口是必须接口。为了使用纯java实现，无法使用android系统库或者其他系统中的事件机制，所以提供了这两个接口让调用方实现。仅需在asyncEventHandler 中的onFire 回调中向调用addRequest的线程post一个事件，事件的处理逻辑就是调用pump接口。asyncEventHandler 中的onFire 回调线程具有不确定性，由于整个Client都不是线程安全的，为了保证线程安全，需要调用pump接口的线程与调用addRequest的线程是同一个线程。在demo中模拟了一个简单的事件循环机制，列出了setAsyncEventHandler与pump的调用范例。
2.	不关注的参数可以传入null。


## Push
每一条会话都有一个变量session_token来标示，对于不同主机名的所有主机，session_token是唯一的。在配置中使用$session_token即可取到session_token的值。后端服务器向客户端推送时，使用host:port标示主机，利用推送协议向主机发送数据，即可推送给客户端。push SDK提供了php的实现。通过http_proxy_set_header Token $session_token，后端服务器解析头域Token 即可得到$session_token的值，即可向指定的客户端推送(头域名字Token可自行设定)。

>	推送协议
>	request:
>		sequece | token | len | data
>		sizeof(sequece) = 4. net order
>		sizeof(token) = 32 . hex
>		sizeof(len) = 4. len = sizof(data) net order
>
>	response:
>		sequece | state
>		sizeof(sequece) = 4. net order
>		sizeof(state) = 1. --- 0: success; 1: hostname error; 2: token not exist


## 变量的说明
1.	变量是与session绑定的，session结束，变量自动销毁，设置的变量都存在于session中，不同的session的同一个变量名没有任何关系。
2.	通过set 与 set_if_empty 设置的变量，在session建立后，变量就存在session中，set命令会覆盖set_if_empty设置的同名变量。通过http_proxy_set_session 可以修改变量的值。
3.	有一个特殊变量session_token在session建立后，自动生成，无需设置，也不能对其设置。
4.	http_proxy_set_header 使用变量的查找顺序为：首先查找该请求的headers的key中是否有此变量名，如果有，就取其值；如果没有，再查找session中是否有此变量，如果有就取其值；如果没有再使用http_proxy_set_header_if_empty命令设置的值，如果没有设置，则取值失败，在http头域中就不会存在该项。
5.	http_proxy_set_uri 后面的参数可以使用常量也可以使用变量，如果是变量，同4的查找策略，如果没有查找到，则使用‘/’。 

## http请求的post get说明
1.	如果body参数不为空，后端的http请求会使用POST协议，如果为空，则使用GET协议。
2.	如果body和header都为空，一样会发起http请求，使用GET协议。
3.	GET协议如何加参数？直接在headers中增加uri的键值对，value为参数拼接好后的字符串，服务器端配置http_proxy_set_uri $uri 

## ssl支持
1.  服务器编译：需要另外加入编译参数 --with-stream_ssl_module
2.  服务器配置：使用stream配置ssl的方法配置，常用命令为：ssl_certificate  ssl_certificate_key ssl_password_file
3.  js 使用ssl: 由原来的ws:// 变更为 wss://
4.  ios/android 使用ssl: 在host前面加入 ssl://

