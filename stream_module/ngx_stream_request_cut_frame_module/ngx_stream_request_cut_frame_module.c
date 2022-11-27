//
//  ngx_stream_request_cut_frame_module.c
//  nginx-1.12
//
//  Created by xpwu on 2019/1/31.
//  Copyright © 2019 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>

#define PROTOCOL_RESPONSE_SUCCESS 0
#define PROTOCOL_RESPONSE_FAILED 1

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_cut_frame_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

static void *ngx_stream_cut_frame_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_cut_frame_merge_srv_conf(ngx_conf_t *cf
                                                  , void *parent, void *child);
char *cut_frame_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_stream_cut_frame_commands[] = {
  
  { ngx_string("cut_frame_protocol"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    cut_frame_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
 
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_cut_frame_module_ctx = {
  NULL,
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  ngx_stream_cut_frame_create_srv_conf,   /* create server configuration */
  ngx_stream_cut_frame_merge_srv_conf     /* merge server configuration */
};

ngx_module_t  ngx_stream_request_cut_frame_module = {
  NGX_MODULE_V1,
  &ngx_stream_cut_frame_module_ctx,           /* module context */
  ngx_stream_cut_frame_commands,              /* module directives */
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


//  heartbeat
typedef void (*start_heartbeat_timer)();
typedef void (*clear_heartbeat_timer_after_send_else)();
typedef void (*clear_heartbeat_timer)();
typedef void (*send_heartbeat)();

typedef struct {
  start_heartbeat_timer start;
  clear_heartbeat_timer_after_send_else clear_after_else;
  clear_heartbeat_timer clear;
  send_heartbeat send;
} heartbeart;





