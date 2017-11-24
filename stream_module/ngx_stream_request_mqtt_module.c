//
//  ngx_stream_request_mqtt_module.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2017/11/22.
//  Copyright © 2017年 xpwu. All rights reserved.
//

/*
 mqtt 协议：
 https://mcxiaoke.gitbooks.io/mqtt-cn/content/mqtt/02-ControlPacketFormat.html
 
 这里主要处理分帧，把长连接转短连接，处理心跳，其他由后端逻辑处理
 
 */

#include "ngx_stream_request_core_module.h"
#include "ngx_stream_util.h"

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_mqtt_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

char *mqtt_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_stream_mqtt_commands[] = {
    
  { ngx_string("mqtt_protocol"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    mqtt_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  ngx_null_command
};

static ngx_stream_module_t  ngx_stream_mqtt_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  NULL,   /* create server configuration */
  NULL     /* merge server configuration */
};

ngx_module_t  ngx_stream_request_mqtt_module = {
  NGX_MODULE_V1,
  &ngx_stream_mqtt_module_ctx,           /* module context */
  ngx_stream_mqtt_commands,              /* module directives */
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


char *mqtt_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  cscf->init_parser = init_parse;
  cscf->build_response = build_response_handler;
  cscf->parse_request = parse_request_handler;
  
  return NGX_CONF_OK;
}

static ngx_stream_request_t* parse_head(ngx_stream_session_t*);
static ngx_stream_request_t* parse_length(ngx_stream_session_t*);
static ngx_stream_request_t* parse_data(ngx_stream_session_t*);

typedef struct {
  ngx_stream_request_t* (*parse_request)(ngx_stream_session_t*);
  ngx_stream_request_t* r;
  ngx_buf_t* buffer;
  ngx_uint_t length; // 表示还要读多少
} mqtt_ctx_t;

static void init_parse(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  
  mqtt_ctx_t* ctx = ngx_pcalloc(c->pool, sizeof(mqtt_ctx_t));
  ctx->parse_request = parse_head;
  
  ngx_add_timer(c->read, 2*cscf->heartbeat);
  
  ngx_stream_set_ctx(s, ctx, this_module);
}

static ngx_stream_request_t* parse_request_handler (ngx_stream_session_t* s) {
  mqtt_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  return ctx->parse_request(s);
}

#define REQUEST_AGAIN (ngx_stream_request_t*) NGX_AGAIN
#define REQUEST_DONE (ngx_stream_request_t*) NGX_DONE

static ngx_stream_request_t* read_buffer(ngx_stream_session_t* s, ngx_uint_t cnt) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  mqtt_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ssize_t n = c->recv(c, ctx->buffer->last
                      , cnt - (ctx->buffer->last - ctx->buffer->pos));
  if (n <= 0 && n != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (n == NGX_AGAIN) {
    ngx_add_timer(c->read, cscf->request_timeout);
    return REQUEST_AGAIN;
  }
  ctx->buffer->last += n;
  if (ctx->buffer->last - ctx->buffer->pos < (ssize_t)cnt) {
    ngx_add_timer(c->read, cscf->request_timeout);
    return REQUEST_AGAIN;
  }
  return REQUEST_DONE;
}

static ngx_stream_request_t* parse_head(ngx_stream_session_t* s) {
  mqtt_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  ngx_log_t* log = s->connection->log;
  
  if (ctx->r == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log
                   , 0, "mqtt new request");
    ctx->r = ngx_stream_new_request(s);
    ctx->r->data = ngx_pcalloc(ctx->r->pool, sizeof(ngx_chain_t));
    ctx->r->data->buf = ngx_create_temp_buf(ctx->r->pool, 200);
    ctx->buffer = ctx->r->data->buf;
    ctx->length = 0;
  }
  
  ssize_t n = c->recv(c, ctx->buffer->last, 1);
  if (n <= 0 && n != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (n == NGX_AGAIN) {
    ngx_add_timer(c->read, 2*cscf->heartbeat);
    return NULL;
  }
  
  ctx->buffer->last += n;
  ctx->parse_request = parse_length;
  
  return NULL;
}

static ngx_stream_request_t* parse_length(ngx_stream_session_t* s) {
  mqtt_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  ngx_log_t* log = s->connection->log;
  
  ngx_uint_t len_length = 0;
  do {
    len_length = ctx->buffer->last-ctx->buffer->pos - 1;
    
    ssize_t n = c->recv(c, ctx->buffer->last, 1);
    if (n <= 0 && n != NGX_AGAIN) {
      return NGX_STREAM_REQUEST_ERROR;
    }
    if (n == NGX_AGAIN) {
      ngx_add_timer(c->read, cscf->request_timeout);
      return NULL;
    }
    
    ctx->buffer->last += 1;
    u_char* p = ctx->buffer->last - 1;
    
    if ((p[0] & 0x80) == 0) {
      // 最后一个字节
      p = ctx->buffer->pos;
      
      ngx_uint_t multiplier = 1;
      ctx->length = 0;
      do {
        p++;
        ctx->length += (*p & 127) * multiplier;
        multiplier *= 128;
      }while (p != ctx->buffer->last);
      
      if (ctx->length == 0) {
        ngx_stream_request_t* r = ctx->r;
        
        ctx->r = NULL;
        ctx->buffer = NULL;
        ctx->length = 0;
        ctx->parse_request = parse_head;
        
        ngx_log_error(NGX_LOG_INFO, log, 0, "mqtt get a frame");
        
        if (r->data->buf->pos[0] == 0xc0) {
          r->data->buf->pos[0] = 0xa0;
          handle_request_done(r);
          return NULL;
        }
        
        return r;
      }
      
      if (ctx->buffer->end - ctx->buffer->last < ctx->length) {
        ctx->r->data->next = ngx_pcalloc(ctx->r->pool, sizeof(ngx_chain_t));
        ctx->r->data->next->buf = ngx_create_temp_buf(ctx->r->pool, ctx->length);
        ctx->buffer = ctx->r->data->next->buf;
      }
      ctx->parse_request = parse_data;
      return NULL;
    }
  } while (len_length < 4);
  
  ngx_log_error(NGX_LOG_ERR, log, 0, "mqtt finalize session because len_length>=4");
  return NGX_STREAM_REQUEST_ERROR;
}

static ngx_stream_request_t* parse_data(ngx_stream_session_t* s) {
  mqtt_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  ngx_log_t* log = s->connection->log;
  
  ssize_t n = c->recv(c, ctx->buffer->last, ctx->length);
  if (n <= 0 && n != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (n == NGX_AGAIN) {
    ngx_add_timer(c->read, cscf->request_timeout);
    return NULL;
  }
  
  ctx->buffer->last += n;
  ctx->length -= n;
  
  if (ctx->length == 0) {
    ngx_stream_request_t* r = ctx->r;
    
    ctx->r = NULL;
    ctx->buffer = NULL;
    ctx->length = 0;
    ctx->parse_request = parse_head;
    
    ngx_log_error(NGX_LOG_INFO, log, 0, "mqtt get a frame");
    
    return r;
  }
}

static void build_response_handler(ngx_stream_request_t* r) {
  if (r->response_status == RESPONSE_STATUS_FAILED) {
    r->data->buf->last = r->data->buf->pos;
    r->data->next = NULL;
    return;
  }
}




