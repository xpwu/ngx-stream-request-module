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

typedef struct ngx_stream_request_s ngx_stream_request_t;
typedef struct ngx_stream_request_upstream_s ngx_stream_request_upstream_t;

#include <ngx_stream_request_variables.h>
#include <ngx_stream_request_script.h>
#include <ngx_stream_request_upstream.h>

typedef struct ngx_stream_request_cleanup_s ngx_stream_request_cleanup_t;
typedef struct ngx_stream_cleanup_s ngx_stream_cleanup_t;
typedef void (*ngx_stream_cleanup_pt)(void *data);
typedef void (*ngx_stream_request_cleanup_pt)(void *data);

#define NGX_STREAM_REQUEST_ERROR (ngx_stream_request_t*)NGX_ERROR

#define ngx_stream_request_get_module_ctx(r, module)   (r)->ctx[module.ctx_index]
#define ngx_stream_request_set_ctx(r, c, module)       r->ctx[module.ctx_index] = c;
#define ngx_stream_request_delete_ctx(r, module)       r->ctx[module.ctx_index] = NULL;

extern void ngx_stream_finalize_session_r(ngx_stream_session_t *s, char* reason);

extern ngx_stream_request_t* ngx_stream_new_request(ngx_stream_session_t*);
/*  run loop  */
extern void ngx_stream_handle_request(ngx_stream_request_t*);

extern void ngx_stream_request_regular_data(ngx_stream_request_t*);

extern ngx_stream_cleanup_t * ngx_stream_cleanup_add(ngx_stream_session_t *s);
extern ngx_stream_request_cleanup_t *
ngx_stream_request_cleanup_add(ngx_stream_request_t*);

extern ngx_module_t  ngx_stream_request_core_module;
/* request protol must set this function to ngx_stream_core_srv_conf_t->handler */
extern void ngx_stream_request_core_handler(ngx_stream_session_t *s);

struct ngx_stream_request_s{
  ngx_stream_session_t* session;
  ngx_stream_request_upstream_t* upstream;
  
  ngx_pool_t* pool;
  
  ngx_chain_t* data; // in / out
  
  void** ctx;
  
  ngx_stream_request_variable_value_t   *variables;
#if (NGX_PCRE)
  ngx_uint_t                     ncaptures;
  int                           *captures;
  u_char                        *captures_data;
#endif
  
  ngx_stream_request_cleanup_t* cln;
  
  ngx_int_t handler_index; 
  
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

typedef struct {
  /* NGX_OK; NGX_AGAIN; NGX_ERROR */
  ngx_int_t (*handle_request)(ngx_stream_request_t*);
  ngx_int_t (*build_response)(ngx_stream_request_t*);
} ngx_stream_request_handler_t;

typedef struct{
  // client
  ngx_msec_t                       heartbeat;
  ngx_msec_t                       receive_from_client_timeout;
  ngx_msec_t                       send_to_client_timeout;
  
  // upstream
  ngx_msec_t                       send_timeout;
  ngx_msec_t                       receive_timeout;
  ngx_msec_t                       response_timeout;
  ngx_msec_t                       next_upstream_timeout; //查找next upstream 的最长时间
  ngx_uint_t                       next_upstream_tries; //next upstream 的最大重试次数
  ngx_flag_t                       next_upstream; //是否自动寻找下一个
  ngx_msec_t                       connect_timeout; // connect upstream 的超时时间
  
  ngx_addr_t                      *local;
  
  ngx_stream_upstream_srv_conf_t* upstream;
  
  // request protocol
  void (*init_parser)(ngx_stream_session_t*);
  ngx_stream_request_t* (*parse_request)(ngx_stream_session_t*);
  void (*build_response)(ngx_stream_request_t*);
  
  ngx_array_t handlers; /*  ngx_stream_request_handler_t */
}ngx_stream_request_core_srv_conf_t;

ngx_stream_request_handler_t*
ngx_stream_request_add_handler(ngx_stream_request_core_srv_conf_t*);

#endif /* ngx_stream_request_h */


