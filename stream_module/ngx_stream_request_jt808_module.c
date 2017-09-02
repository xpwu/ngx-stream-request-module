//
//  ngx_stream_request_jt808_module.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2017/9/2.
//  Copyright © 2017年 xpwu. All rights reserved.
//


// JT/T 808-2013《道路运输车辆卫星定位系统 终端通讯协议及数据格式》
/**
 
 这里主要处理 分帧、数据还原、校验、其他的逻辑操作由后台服务器完成
 
 向终端发送消息时使用push 接口，检验位与转义 由这里处理
 
 流水号等由后端服务器自己维护
 
 */

#include "ngx_stream_request_core_module.h"
#include "ngx_stream_util.h"

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_jt808_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

char *jt808_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_stream_jt808_commands[] = {
  
  { ngx_string("jt808_protocol"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    jt808_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  ngx_null_command
};

static ngx_stream_module_t  ngx_stream_jt808_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  NULL,   /* create server configuration */
  NULL     /* merge server configuration */
};

ngx_module_t  ngx_stream_request_jt808_module = {
  NGX_MODULE_V1,
  &ngx_stream_jt808_module_ctx,           /* module context */
  ngx_stream_jt808_commands,              /* module directives */
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


static void init_parse(ngx_stream_session_t* s);
static void build_response_handler(ngx_stream_request_t* r);
static ngx_stream_request_t* parse_request_handler (ngx_stream_session_t* s);


char *jt808_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  cscf->init_parser = init_parse;
  cscf->build_response = build_response_handler;
  cscf->parse_request = parse_request_handler;
  
  return NGX_CONF_OK;
}


typedef struct {
  ngx_buf_t* buffer;
  ngx_stream_request_t* r;
} jt808_ctx_t;


static void init_parse(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  
  jt808_ctx_t* ctx = ngx_pcalloc(c->pool, sizeof(jt808_ctx_t));
  ctx->buffer = ngx_create_temp_buf(c->pool, 150);
  
  ngx_add_timer(c->read, 2*cscf->heartbeat);
  
  ngx_stream_set_ctx(s, ctx, this_module);
}

static ngx_stream_request_t* parse_request_handler (ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
    = ngx_stream_get_module_srv_conf(s, core_module);
  jt808_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_log_t* log = s->connection->log;
  
  ngx_regular_buf(ctx->buffer);
  
  ssize_t re = c->recv(c, ctx->buffer->last
                       , ctx->buffer->end - ctx->buffer->last);
  if (re < 0 && re != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (re == NGX_AGAIN) {
    re = 0;
  }
  
  ctx->buffer->last += re;
  
  if (ngx_buf_size(ctx->buffer) == 0) {
    return NULL;
  }
  
  ngx_stream_request_t* result = NULL;
  
  while (ctx->buffer->pos != ctx->buffer->last) {
    if (ctx->r == NULL && ctx->buffer->pos[0] == 0x7e) { // 帧头的0x7e
      ctx->buffer->pos++;
      continue;
    }
    
    if (ctx->r == NULL) {
      ctx->r = ngx_stream_new_request(s);
      ctx->r->data = ngx_pcalloc(ctx->r->pool, sizeof(ngx_chain_t));
      // 为了逻辑简单，目前的协议中，最大一帧的长度不超过150
      // 省去了考虑多个buffer组成chain的情况
      ctx->r->data->buf = ngx_create_temp_buf(ctx->r->pool, 150);
    }
    
    if (ctx->buffer->pos[0] == 0x7e) { // 帧尾
      result = ctx->r;
      ctx->r = NULL;
      ctx->buffer->pos++;
      // check
      char xor = 0x00;
      for (u_char* p = result->data->buf->pos;
           p != result->data->buf->last; ++p) {
        xor ^= p[0];
      }
      if (xor != 0x00) {
        return NGX_STREAM_REQUEST_ERROR;
      }
      result->data->buf->last--;
      break;
    }
    
    if (ctx->buffer->pos[0] == 0x7d
        && ngx_buf_size(ctx->buffer) == 1) { //无法还原转义，等待更多的数据
      break;
    }
    
    ngx_buf_t* dest = ctx->r->data->buf;
    
    if (ctx->buffer->pos[0] == 0x7d) {
      if (ctx->buffer->pos[1] == 0x02) {
        dest->last[0] = 0x7e;
      } else if (ctx->buffer->pos[1] == 0x01) {
        dest->last[0] = 0x7d;
      } else {
        return NGX_STREAM_REQUEST_ERROR;
      }
      
      ctx->buffer->pos += 2;
      dest->last ++;
      continue;
    }
  
    dest->last[0] = ctx->buffer->pos[0];
    ctx->buffer->pos++;
    dest->last++;
  }
  
  if (ngx_buf_size(ctx->buffer) > 1
      || (ngx_buf_size(ctx->buffer)==1
          && ctx->buffer->pos[0] != 0x7d)) {
    // 当读出的buffer还有数据时，无论网络层是否还有数据，都需要再次放到事件循环中
    ngx_post_event(c->read, &ngx_posted_events);
  }
  
  ngx_add_timer(c->read, 2*cscf->heartbeat);
  
  return result;
}

static void build_response_handler(ngx_stream_request_t* r) {
  ngx_buf_t* temp = ngx_create_temp_buf(r->pool
              , 2*(1+ngx_buf_size(r->data->buf)));
  
  ngx_buf_t* src = r->data->buf;
  
  char xor = 0x00;
  for (u_char* p = src->pos; p != src->last; ++p) {
    xor ^= p[0];
  }
  
  while (src->pos != src->last) {
    if (src->pos[0] == 0x7d) {
      temp->last[0] = 0x7d;
      temp->last[1] = 0x01;
      
      temp->last += 2;
      src->pos++;
      continue;
    }
    
    if (src->pos[0] == 0x7e) {
      temp->last[0] = 0x7d;
      temp->last[1] = 0x02;
      
      temp->last += 2;
      src->pos++;
      continue;
    }
    
    temp->last[0] = src->pos[0];
    temp->last++;
    src->pos++;
  }
  
  if (xor == 0x7d) {
    temp->last[0] = 0x7d;
    temp->last[1] = 0x01;
    temp->last += 2;
  }
  if (xor == 0x7e) {
    temp->last[0] = 0x7d;
    temp->last[1] = 0x02;
    temp->last += 2;
  }
  
  r->data->buf = temp;
}


