//
//  ngx_stream_request_module.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/12/8.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

static ngx_command_t  null_commands[] = {
  ngx_null_command
};

static ngx_stream_module_t  null_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  NULL,   /* create server configuration */
  NULL     /* merge server configuration */
};

ngx_module_t  ngx_stream_request_module = {
  NGX_MODULE_V1,
  &null_ctx,           /* module context */
  null_commands,              /* module directives */
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


