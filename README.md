# ngx-stream-request-module



##简介
实现客户端到服务器的长连接通信, 客户端与服务器之间仅需一条长连接就可实现客户端到服务器get数据,以及服务器向客户端push数据. 无需更改服务器逻辑即可实现现有的http短连接方式升级到长连接. 支持 ios android web

##名词解释
* 会话(session): 客户端与服务器建立连接后就形成一次会话, 一次连接对应一次会话, 不同的连接对应不同的会话. 因此对于服务器来书, 一个会话能唯一标示一个客户端.
* 请求(request): 客户端向服务器发起的一次数据交换. 请求是在会话中传输, 一个会话可以传输若干请求, 同一个会话的所有请求可以共享该会话已有的数据(见服务器部分). 请求在会话中的传输是异步的, 下一个请求的传输不需要等待上一个请求结束后再传输, 可以简单认为请求是在会话上并行传输(有一种情况例外, 见客户端服务).

##服务器
目前仅支持nginx 1.10

* 编译: 目前仅支持静态编译, 假如stream_module的路径为/path/to/stream_module, 使用 --add-module=/path/to/stream_module 参数即可把模块编入nginx 中, 具体可以参加nginx的三方模块编译说明文档.
* 配置: 此模块属于stream核心模块, 因此需要在stream 部分配置, stream 原有的server listen error_log等命令继续使用.

    |    命令             |     参数           | 说明                  |
    |:------------------:|:-----------------:|:--------------------|
    | session_request    | 无                 | stream 切入session_request模式, 必须配置|
    |以下3个配置为协议配置, 一个server 至少配置其中一种协议|||
    |lencontent_protocol | 无                 | 主要用于ios与android|
    |websocket_protocol  | 无                 | 主要用于web|
    |push_protocol       | 无                 |主要用于push|
    |以下为session参数的设置|||
    |set|两个参数|第一个参数为session变量, 第二个参数为值. <br>第一个参数必须以$开头. <br>例如: set $name xpwu, 表示把session的name变量设置为xpwu.<br> 此设置对连接到此服务的任何session都进行了设置|
    |set_if_empty|两个参数|参数意义与set相同. 此命令在session的变量为空时, 才设置变量的值, 实际中使用较少|
    | 以下为使用websocket协议的服务设置|||
    |ws_access_origins|一个参数|设置允许通信的origin连接, 默认值为全部都允许通信.<br>重复使用该命令, 可以加入多个允许通信的连接.<br> 设置为'all', 表示允许全部连接通信, 与默认值的表现一致|
    |ws_handshake_timeout|一个参数, 单位ms| 服务器收到websocket握手信号的最长等待时间|
    
    
  

 
