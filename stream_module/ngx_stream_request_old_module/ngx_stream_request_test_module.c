//
//  ngx_stream_request_test_module.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 16/10/17.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include "ngx_stream_request_core_module.h"
#include "ngx_stream_variable_module.h"

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_test_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

char *test_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_stream_http_proxy_commands[] = {
  
  { ngx_string("request_test"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    test_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  ngx_null_command
};

static ngx_stream_module_t  ngx_stream_http_proxy_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  NULL,   /* create server configuration */
  NULL     /* merge server configuration */
};

ngx_module_t  ngx_stream_request_test_module = {
  NGX_MODULE_V1,
  &ngx_stream_http_proxy_module_ctx,           /* module context */
  ngx_stream_http_proxy_commands,              /* module directives */
  NGX_STREAM_MODULE,                     /* module type */
  NULL,                                  /* init master */
  NULL,                                  /* init module */
  NULL,                                  /* init process */
  NULL,                                  /* init thread */
  NULL,                                  /* exit thread */
  NULL,                                  /* exit process */
  NULL,                                  /* exit master */
  NGX_MODULE_V1_PADDING
};

static void proxy_handle_request(ngx_stream_request_t*);

char *test_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  cscf->init_proxy_handler = NULL;
  cscf->proxy_handle_request = proxy_handle_request;
  
  return NGX_CONF_OK;
}

static void proxy_handle_request(ngx_stream_request_t* r) {
  ngx_chain_t* last = r->data;
  while (last->next != NULL) {
    last = last->next;
  }
  last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  last = last->next;
  last->buf = ngx_create_temp_buf(r->pool, 100);
  u_char res[] = "-->response";
  ngx_memcpy(last->buf->last, res, sizeof(res)-1);
  last->buf->last += sizeof(res)-1;
  
  handle_request_done(r);
}

