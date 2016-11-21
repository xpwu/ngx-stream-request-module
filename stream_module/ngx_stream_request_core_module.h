//
//  ngx_stream_request_core_module.h
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/6.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#ifndef ngx_stream_request_core_module_h
#define ngx_stream_request_core_module_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_str_str_rbtree.h"

typedef struct ngx_stream_request_s ngx_stream_request_t;
typedef struct ngx_stream_request_core_srv_conf_s ngx_stream_request_core_srv_conf_t;
typedef struct ngx_stream_request_core_main_conf_s ngx_stream_request_core_main_conf_t;
typedef struct ngx_stream_cleanup_s ngx_stream_cleanup_t;
typedef void (*ngx_stream_cleanup_pt)(void *data);
typedef struct ngx_stream_request_cleanup_s ngx_stream_request_cleanup_t;
typedef void (*ngx_stream_request_cleanup_pt)(void *data);

enum ngx_stream_request_status{
  RESPONSE_STATUS_SUCCESS = 0,
  RESPONSE_STATUS_FAILED = 1
};

enum ngx_stream_request_type {
  STREAM_REQUEST_NORMAL = 0,
  STREAM_REQUEST_PUSH = 1
};

#define NGX_STREAM_REQUEST_ERROR (ngx_stream_request_t*)NGX_ERROR

struct ngx_stream_request_s {
  ngx_pool_t* pool;
  
  ngx_chain_t* data; // in / out
  ngx_str_str_rbtree* headers;
  
  enum ngx_stream_request_status response_status; // 0: success; 1: failed; else: reserved
  enum ngx_stream_request_type type;
  
  ngx_stream_session_t* session;
  ngx_stream_upstream_t* upstream;
  
  void** ctx;
  ngx_stream_request_cleanup_t* cln;
  
  ngx_queue_t list;
};

#define ngx_stream_request_get_module_ctx(r, module)   (r)->ctx[module.ctx_index]
#define ngx_stream_request_set_ctx(r, c, module)       r->ctx[module.ctx_index] = c;
#define ngx_stream_request_delete_ctx(r, module)       r->ctx[module.ctx_index] = NULL;

struct ngx_stream_request_core_main_conf_s {
  ngx_array_t   session_initializers; // void (*)(ngx_stream_session_t*)
};

struct ngx_stream_request_core_srv_conf_s {
  ngx_msec_t                       connect_timeout;
  ngx_msec_t                       send_to_client_timeout;
  ngx_msec_t                       next_upstream_timeout;
  ngx_uint_t                       next_upstream_tries;
  ngx_flag_t                       next_upstream;
  ngx_addr_t                      *local;
  ngx_flag_t                       send_error_log_to_client;
  
#if (NGX_STREAM_SSL)
  ngx_flag_t                       ssl_enable;
  ngx_flag_t                       ssl_session_reuse;
  ngx_uint_t                       ssl_protocols;
  ngx_str_t                        ssl_ciphers;
  ngx_str_t                        ssl_name;
  ngx_flag_t                       ssl_server_name;
  
  ngx_flag_t                       ssl_verify;
  ngx_uint_t                       ssl_verify_depth;
  ngx_str_t                        ssl_trusted_certificate;
  ngx_str_t                        ssl_crl;
  ngx_str_t                        ssl_certificate;
  ngx_str_t                        ssl_certificate_key;
  ngx_array_t                     *ssl_passwords;
  
  ngx_ssl_t                       *ssl;
#endif
  ngx_stream_upstream_srv_conf_t* upstream;
  
  // request parser
  void (*init_parser)(ngx_stream_session_t*);
  ngx_stream_request_t* (*parse_request)(ngx_stream_session_t*);
  void (*build_response)(ngx_stream_request_t*);
  
  void (*init_proxy_handler)(ngx_stream_request_t*);
  void (*proxy_handle_request)(ngx_stream_request_t*);
};

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


extern void ngx_stream_finalize_session_r(ngx_stream_session_t *s, char* reason);
extern void ngx_stream_request_failed(ngx_stream_request_t *r, char* reason);


extern ngx_stream_request_t* ngx_stream_new_request(ngx_stream_session_t*);
extern void handle_request_done(ngx_stream_request_t*);

extern void ngx_regular_request_data(ngx_stream_request_t*);

extern void ngx_regular_buf(ngx_buf_t* buf);
extern ngx_uint_t ngx_chain_len(ngx_chain_t* chain);

extern ngx_stream_cleanup_t * ngx_stream_cleanup_add(ngx_stream_session_t *s);
extern ngx_stream_request_cleanup_t *
ngx_stream_request_cleanup_add(ngx_stream_request_t*);

extern void ngx_stream_request_set_header(ngx_stream_request_t *r
                                          , ngx_str_t key, ngx_str_t value);
extern ngx_str_t ngx_stream_request_get_header(ngx_stream_request_t *r
                                               , ngx_str_t key);

extern ngx_module_t ngx_stream_request_core_module;

#endif /* ngx_stream_request_core_module_h */
