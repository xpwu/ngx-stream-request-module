//
//  ngx_stream_request.h
//  nginx-1.12
//
//  Created by xpwu on 2017/12/16.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#ifndef ngx_stream_request_h
#define ngx_stream_request_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <ngx_str_str_rbtree.h>
#include <ngx_radix64_tree.h>

#define NGX_HANDLER_STOP NGX_DECLINED

typedef struct ngx_stream_request_s ngx_stream_request_t;
typedef struct ngx_stream_request_upstream_s ngx_stream_request_upstream_t;
typedef struct ngx_stream_request_core_srv_conf_s ngx_stream_request_core_srv_conf_t;
typedef struct ngx_stream_request_handler_s ngx_stream_request_handler_t;
typedef struct ngx_stream_request_protocol_s ngx_stream_request_protocol_t;

#include <ngx_stream_request_variables.h>
#include <ngx_stream_request_script.h>
#include <ngx_stream_request_upstream.h>

typedef struct ngx_stream_request_cleanup_s ngx_stream_request_cleanup_t;
typedef struct ngx_stream_cleanup_s ngx_stream_cleanup_t;
typedef void (*ngx_stream_cleanup_pt)(void *data);
typedef void (*ngx_stream_request_cleanup_pt)(void *data);

#define NGX_STREAM_REQUEST_ERROR (ngx_stream_request_t*)NGX_ERROR
#define NGX_STREAM_REQUEST_AGAIN (ngx_stream_request_t*)NULL

#define ngx_stream_request_get_module_ctx(r, module)   (r)->ctx[module.ctx_index]
#define ngx_stream_request_set_ctx(r, c, module)       r->ctx[module.ctx_index] = c;
#define ngx_stream_request_delete_ctx(r, module)       r->ctx[module.ctx_index] = NULL;

extern void ngx_stream_finalize_session_r(ngx_stream_session_t *s, char* reason);
extern void ngx_stream_finalize_session_r_level(ngx_stream_session_t *s
                                                , char* reason
                                                , ngx_uint_t level);
extern ngx_stream_request_t* ngx_stream_new_request(ngx_stream_session_t*);
/*  run loop  */
extern void ngx_stream_handle_request(ngx_stream_request_t*);
// 从index个的response方向开始处理request. response: 1/0
// index < 0 表示从后向前的index. -1: 最后一个
extern void ngx_stream_handle_request_from(ngx_stream_request_t*
                                           , ngx_int_t index, ngx_int_t response);

extern ngx_stream_request_handler_t* ngx_stream_request_add_handler(ngx_conf_t*);

extern void ngx_stream_request_regular_data(ngx_stream_request_t*);
extern void ngx_stream_request_set_data(ngx_stream_request_t*, char* err_info);

extern ngx_stream_cleanup_t * ngx_stream_cleanup_add(ngx_stream_session_t *s);
extern ngx_stream_request_cleanup_t *
ngx_stream_request_cleanup_add(ngx_stream_request_t*);

extern ngx_module_t  ngx_stream_request_core_module;
/* protolcol must set this function to ngx_stream_core_srv_conf_t->handler */
extern void ngx_stream_request_core_handler(ngx_stream_session_t *s);

extern void ngx_regular_buf(ngx_buf_t* buf);
extern ngx_uint_t ngx_chain_len(ngx_chain_t* chain);
extern ngx_array_t* ngx_merge_key_val_array(ngx_pool_t* pool, ngx_array_t* parent
                                            , ngx_array_t* child);

#define NGX_STREAM_REQUEST_SUBPROTOCOL_ANY -1

struct ngx_stream_request_s{
  ngx_stream_session_t* session;
  ngx_stream_request_upstream_t* upstream;
  
  ngx_pool_t* pool;
  
  // NGX_STREAM_REQUEST_SUBPROTOCOL_ANY: 表示不关注具体的子协议
  ngx_int_t subprotocol_flag;
  
  ngx_chain_t* data; // in / out
  ngx_int_t   error; // 标示data中的数据
  
  void** ctx;
  
  ngx_stream_request_variable_value_t   *variables;
#if (NGX_PCRE)
  ngx_uint_t                     ncaptures;
  int                           *captures;
  u_char                        *captures_data;
#endif
  
  ngx_stream_request_cleanup_t* cln;
  
  char* close_reason; // 当数据发送结束时，是否关闭连接，和关闭原因
  
  ngx_queue_t list;
} ;

struct ngx_stream_cleanup_s {
  ngx_stream_cleanup_pt     handler;
  void                      *data;
  ngx_stream_cleanup_t      *next;
};

struct ngx_stream_request_cleanup_s {
  ngx_stream_request_cleanup_pt     handler;
  void                              *data;
  ngx_stream_request_cleanup_t      *next;
};

typedef struct {
  ngx_hash_t                     variables_hash;
  
  ngx_array_t                    variables;        /* ngx_stream_variable_t */
  ngx_array_t                    prefix_variables; /* ngx_stream_variable_t */
  ngx_uint_t                     ncaptures;
  
  ngx_uint_t                     variables_hash_max_size;
  ngx_uint_t                     variables_hash_bucket_size;
  
  ngx_hash_keys_arrays_t        *variables_keys;
  
} ngx_stream_request_core_main_conf_t;

struct ngx_stream_request_handler_s{
  // NGX_STREAM_REQUEST_SUBPROTOCOL_ANY: 表示不关注具体的子协议
  ngx_int_t subprotocol_flag;
  ngx_int_t index; // set by ngx_stream_request_add_handler
  char* name;
  /* NGX_OK; NGX_AGAIN; NGX_ERROR; NGX_HANDLER_STOP */
  ngx_int_t (*handle_request)(ngx_stream_request_t*);
  ngx_int_t (*build_response)(ngx_stream_request_t*);
};

struct ngx_stream_request_protocol_s {
  void (*init_parser)(ngx_stream_session_t*);
  ngx_stream_request_t* (*get_request)(ngx_stream_session_t*);
  
  ngx_stream_request_handler_t handler;
};

struct ngx_stream_request_core_srv_conf_s{
  // client
  ngx_msec_t                       heartbeat;
  ngx_msec_t                       receive_from_client_timeout;
  ngx_msec_t                       send_to_client_timeout;
  
  // upstream
  ngx_msec_t                       send_to_proxy_timeout;
  ngx_msec_t                       receive_from_proxy_timeout;
  ngx_msec_t                       proxy_response_timeout;
  ngx_msec_t                       next_upstream_timeout; //查找next upstream 的最长时间
  ngx_uint_t                       next_upstream_tries; //next upstream 的最大重试次数
  ngx_flag_t                       next_upstream; //是否自动寻找下一个
  ngx_msec_t                       connect_timeout; // connect upstream 的超时时间
  
  ngx_addr_t                      *local;
  
  ngx_stream_upstream_srv_conf_t* upstream;
  
  ngx_stream_request_protocol_t protocol;
  
  ngx_array_t handlers; /*  ngx_stream_request_handler_t */
};


#endif /* ngx_stream_request_h */


