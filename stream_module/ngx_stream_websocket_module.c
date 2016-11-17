//
//  ngx_stream_websocket_module.c
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/8.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include "ngx_stream_extend_module.h"

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_websocket_module

static void *ngx_stream_websocket_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_websocket_merge_srv_conf(ngx_conf_t *cf
                                                , void *parent, void *child);
char *websocket_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_stream_websocket_handler(ngx_stream_session_t *s);

typedef struct websocket_srv_conf_s {
  ngx_array_t*  access_origins;
  ngx_msec_t  handshake_timeout;
}websocket_srv_conf_t;


static ngx_command_t  ngx_stream_websocket_commands[] = {
  
  { ngx_string("websocket"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    websocket_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  { ngx_string("ws_access_orign"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(websocket_srv_conf_t, access_origins),
    NULL},
  
  { ngx_string("ws_handshake_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(websocket_srv_conf_t, handshake_timeout),
    NULL},
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_websocket_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  ngx_stream_websocket_create_srv_conf,   /* create server configuration */
  ngx_stream_websocket_merge_srv_conf     /* merge server configuration */
};


ngx_module_t  ngx_stream_websocket_module = {
  NGX_MODULE_V1,
  &ngx_stream_websocket_module_ctx,           /* module context */
  ngx_stream_websocket_commands,              /* module directives */
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

#pragma mark - conf

static void *ngx_stream_websocket_create_srv_conf(ngx_conf_t *cf) {
  websocket_srv_conf_t  *wscf;
  
  wscf = ngx_pcalloc(cf->pool, sizeof(websocket_srv_conf_t));
  if (wscf == NULL) {
    return NULL;
  }
  
  /*
   * set by ngx_pcalloc():
   */
  
//  wscf->handshake_timeout = NGX_CONF_UNSET_MSEC;
  wscf->access_origins = NGX_CONF_UNSET_PTR;
  wscf->handshake_timeout = NGX_CONF_UNSET_MSEC;
  
  return wscf;
}

static char *ngx_stream_websocket_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child) {
  websocket_srv_conf_t *prev = parent;
  websocket_srv_conf_t *conf = child;
  
  ngx_conf_merge_ptr_value(conf->access_origins, prev->access_origins, NULL);
  ngx_conf_merge_msec_value(conf->handshake_timeout, conf->handshake_timeout, 30000);
  
  return NGX_CONF_OK;
}

char *websocket_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_extend_add_handler(cf, ngx_stream_websocket_handler);
  return NGX_CONF_OK;
}

#pragma mark - handler

typedef struct{
  ngx_uint_t sec_websocket_version;
//  ngx_buf_t* recv_handshake_buffer;
  ngx_str_t sec_websocket_key;
  ngx_str_t origin;
  ngx_int_t first_line;
  ngx_int_t last_is_crlf;
  ngx_pool_t* pool;
} handshake_ctx_t;

typedef struct {
  handshake_ctx_t* handshake_ctx;
  
  ngx_recv_pt old_recv;
  ngx_send_pt old_send;
  ngx_recv_chain_pt old_recv_chain;
  ngx_send_chain_pt old_send_chain;
  
  ngx_buf_t* recv_buffer;

}ngx_stream_session_websocket_ctx_t;

static void ws_read_handshake_handler(ngx_event_t* e);
static void ws_write_handshake_handler(ngx_event_t* e);

static ngx_int_t ngx_stream_ugly_ssl_handler(ngx_stream_session_t *s) {
  ngx_stream_session_websocket_ctx_t* ctx
  = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_session_websocket_ctx_t));
  /**
   *  ngx_pcalloc set:
   *
   */
  ctx->recv_buffer = ngx_create_temp_buf(s->connection->pool, 1024);
  
  ngx_pool_t* tmp_pool = ngx_create_pool(1024, s->connection->log);
  handshake_ctx_t* handshake_ctx = ngx_pcalloc(tmp_pool, sizeof(handshake_ctx_t));
  handshake_ctx->pool = tmp_pool;
  ctx->handshake_ctx = handshake_ctx;
  
  
  ngx_stream_set_ctx(s, ctx, this_module);
  
  s->connection->read->handler = ws_read_handshake_handler;
  s->connection->write->handler = ws_write_handshake_handler;
  
  if (ngx_handle_read_event(s->connection->read, 0) != NGX_OK) {
    // TODO: error log
    return NGX_ERROR;
  }
  return NGX_AGAIN;
}

static ngx_int_t parse_handshake(ngx_buf_t* buf, handshake_ctx_t* ctx) {
  ngx_int_t end_head = 0;
  for (u_char* p = buf->pos; p+1 < buf->last; ++p) {
    if (!(*p == CR && *(p+1) == LF)) {
      if (ctx->first_line == 1 && buf->last-buf->pos >= 4) {
        if (buf->pos[0] != 'G' || buf->pos[1] != 'E'
            || buf->pos[2] != 'T' || buf->pos[3] != ' ') {
          return NGX_ERROR;
        }
      }
      ctx->last_is_crlf = 0;
      continue;
    }
    
    if (ctx->last_is_crlf == 1) {
      buf->pos = buf->last;
      end_head = 1;
      break;
    }
    ctx->last_is_crlf = 1;
    if (ctx->first_line == 1) {
      ctx->first_line = 0;
      buf->pos = p+2;
    } else {
      u_char* p1 = buf->pos;
      u_char* p2 = ngx_strlchr(buf->pos, p, ':');
      if (p2 == NULL) {
        return NGX_ERROR;
      }
      u_char* p3 = p2+1;
      while (p1 < p2 && *p1 == ' ') {p1++;}
      while (p1 < p2 && *(p2-1) == ' ') {--p2;}
      *p2 = '\0';
      
      buf->pos = p + 2;
      while (p3 < p && *p3 == ' ') {++p3;}
      while (p3 < p && *(p-1) == ' ') {--p;}
      *p = '\0';
      if (ngx_strcmp(p1, "Sec-WebSocket-Key") == 0) {
        ctx->sec_websocket_key.len = p-p3;
        ctx->sec_websocket_key.data = ngx_pcalloc(ctx->pool, p-p3);
        ngx_memcpy(ctx->sec_websocket_key.data, p3, p-p3);
      }
      if (ngx_strcmp(p1, "Origin") == 0) {
        ctx->origin.len = p-p3;
        ctx->origin.data = ngx_pcalloc(ctx->pool, p-p3);
        ngx_memcpy(ctx->origin.data, p3, p-p3);
      }
      if (ngx_strcmp(p1, "Sec-WebSocket-Version") == 0) {
        ctx->sec_websocket_version = ngx_atoi(p3, p-p3);
      }
      if (ngx_strcmp(p1, "Connection") == 0) {
        if (ngx_strcmp(p3, "Upgrade") != 0) {
          return NGX_ERROR;
        }
      }
      if (ngx_strcmp(p1, "Upgrade") == 0) {
        if (ngx_strcmp(p3, "websocket") != 0) {
          return NGX_ERROR;
        }
      }
      p = buf->pos - 1;
    }
  }
  
  return end_head == 1 ? NGX_OK : NGX_AGAIN;
}

static void ws_read_handshake_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_session_t* s = c->data;
  websocket_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_session_websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  handshake_ctx_t* handshake_ctx = ctx->handshake_ctx;
  
  if (e->timedout) {
    ngx_stream_finalize_session_r(s, "ws_read_handshake_handler timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  ssize_t re = c->recv(c, ctx->recv_buffer->last
                       , ctx->recv_buffer->end-ctx->recv_buffer->last);
  
  if (re <= 0 && re != NGX_AGAIN) {
    ngx_stream_finalize_session_r(s, "ws_read_handshake_handler error");
    return;
  }
  if (re == NGX_AGAIN) {
    ngx_add_timer(e, wscf->handshake_timeout);
    if (ngx_handle_read_event(e, 0) != NGX_OK) {
      ngx_stream_finalize_session_r(s, "ngx_handle_read_event error");
    }
    return;
  }
  
  // TODO: log
  ctx->recv_buffer->last += re;
  
  ngx_int_t result = parse_handshake(buf, ctx);
  if (result == NGX_ERROR) {
    ngx_tcp_websocket_close_session(ws, "parse_handshake error!");
    return;
  }
  regular_buffer(buf);
  if (result == NGX_AGAIN) {
    read_event_time(e, read_handshake_timeout, ws);
    return;
  }
  
}





