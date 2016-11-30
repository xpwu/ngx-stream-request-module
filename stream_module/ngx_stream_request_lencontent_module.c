//
//  ngx_stream_request_lencontent_module.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/11/17.
//  Copyright © 2016年 xpwu. All rights reserved.
//

/**
 *
 *  lencontent protocol:
 *
 *  1, handshake protocol:
 *
 *        client ------------------ server
 *          |                          |
 *          |                          |
 *        ABCDEF (A^...^F = 0xff) --->  check(A^...^F == 0xff) -N--> over
 *          |                          |
 *          |                          |Y
 *          |                          |
 *         data      <-------->       data
 *
 *
 *  2, data protocol:
 *    1) length | content
 *      length: 4 bytes, net order; length=sizeof(content)+4; length=0 => heartbeat
 *
 *    2) content protocol:
 *    request ---
 *      reqid | data
 *        reqid: 4 bytes, net order;
 *
 *    response ---
 *      reqid | status | data
 *        reqid: 4 bytes, net order;
 *        status: 1 byte, 0---success, 1---failed
 *        data: if status==success, data=<app data>
 *              if status==failed, data=<error reason>
 *
 */

#include "ngx_stream_request_core_module.h"
#include "ngx_stream_request_content_logic.h"

#define PROTOCOL_RESPONSE_SUCCESS 0
#define PROTOCOL_RESPONSE_FAILED 1

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_lencontent_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

static void *ngx_stream_lencontent_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_lencontent_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child);
char *lencontent_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct lencontent_srv_conf_s {
  ngx_msec_t  handshake_timeout;
  ngx_msec_t  heartbeat;
  ngx_msec_t  request_timeout;
  
  ngx_flag_t  enc; // 是否开启加密
}lencontent_srv_conf_t;


static ngx_command_t  ngx_stream_lencontent_commands[] = {
  
  { ngx_string("lencontent_protocol"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1|NGX_CONF_NOARGS,
    lencontent_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  { ngx_string("lenc_handshake_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(lencontent_srv_conf_t, handshake_timeout),
    NULL},
  
  { ngx_string("lenc_request_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(lencontent_srv_conf_t, request_timeout),
    NULL},
  
  { ngx_string("lenc_heartbeat"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(lencontent_srv_conf_t, heartbeat),
    NULL},
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_lencontent_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  ngx_stream_lencontent_create_srv_conf,   /* create server configuration */
  ngx_stream_lencontent_merge_srv_conf     /* merge server configuration */
};


ngx_module_t  ngx_stream_request_lencontent_module = {
  NGX_MODULE_V1,
  &ngx_stream_lencontent_module_ctx,           /* module context */
  ngx_stream_lencontent_commands,              /* module directives */
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

static void *ngx_stream_lencontent_create_srv_conf(ngx_conf_t *cf) {
  lencontent_srv_conf_t  *wscf;
  
  wscf = ngx_pcalloc(cf->pool, sizeof(lencontent_srv_conf_t));
  if (wscf == NULL) {
    return NULL;
  }
  
  /*
   * set by ngx_pcalloc():
   *    wscf->enc = 0;
   */
  
  wscf->handshake_timeout = NGX_CONF_UNSET_MSEC;
  wscf->heartbeat = NGX_CONF_UNSET_MSEC;
  wscf->request_timeout = NGX_CONF_UNSET_MSEC;
  
  return wscf;
}

static char *ngx_stream_lencontent_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child) {
  lencontent_srv_conf_t *prev = parent;
  lencontent_srv_conf_t *conf = child;
  
  ngx_conf_merge_msec_value(conf->handshake_timeout, prev->handshake_timeout, 30000);
  ngx_conf_merge_msec_value(conf->heartbeat, prev->heartbeat, 4*60000);
  ngx_conf_merge_msec_value(conf->request_timeout, prev->request_timeout, 10000);
  
  return NGX_CONF_OK;
}

#pragma mark - process request

#define REQUEST_AGAIN (ngx_stream_request_t*) NGX_AGAIN
#define REQUEST_DONE (ngx_stream_request_t*) NGX_DONE
/*  return ngx_stream_request_t*: 解析到一个request
 return REQUEST_AGAIN: 解析数据不够
 return REQUEST_DONE: 进行下一步
 */
typedef ngx_stream_request_t* (*request_handler_t)(ngx_stream_session_t*);

typedef struct {
  u_char temp_buffer[6];
  u_char len;
  
  ngx_event_t timer;
  
  ngx_stream_request_t* r;
  
  request_handler_t handler;
  
  ngx_stream_request_t* (*parse_request)(ngx_stream_session_t*);
  void (*build_response)(ngx_stream_request_t*);
} lencontent_ctx_t;

static void ngx_stream_cleanup_event(void *data) {
  ngx_event_t* timer = data;
  
  if (timer->timer_set) {
    ngx_del_timer(timer);
  }
}

static void init_parse(ngx_stream_session_t* s);
static void build_response_handler(ngx_stream_request_t* r);
static ngx_stream_request_t* parse_request_handler (ngx_stream_session_t* s);

static ngx_stream_request_t* parse_handshake(ngx_stream_session_t*);
//static void build_handshake(ngx_stream_request_t* r);

static void init_parse_request(ngx_stream_session_t* s);
static ngx_stream_request_t* parse_request(ngx_stream_session_t*);
static void build_response(ngx_stream_request_t* r);

char *lencontent_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
//  lencontent_srv_conf_t  *wscf = conf;
//  ngx_str_t* value = cf->args->elts;
//  if (cf->args->nelts == 2) {
//    if (value[1].len != 3 || ngx_memcmp(value[1].data, "enc", 3) != 0) {
//      return "args is 'enc' only";
//    }
//#if (!NGX_STREAM_SSL)
//    return "'enc' must define NGX_STREAM_SSL";
//#endif
//    wscf->enc = 1;
//  }
  
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  cscf->init_parser = init_parse;
  cscf->build_response = build_response_handler;
  cscf->parse_request = parse_request_handler;
  
  return NGX_CONF_OK;
}

static ngx_stream_request_t* parse_request_handler (ngx_stream_session_t* s) {
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  return ctx->parse_request(s);
}

static void build_response_handler(ngx_stream_request_t* r) {
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(r->session, this_module);
  ctx->build_response(r);
}

static void init_parse(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  lencontent_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  lencontent_ctx_t* ctx = ngx_pcalloc(c->pool, sizeof(lencontent_ctx_t));
  
  ngx_add_timer(c->read, wscf->handshake_timeout);
  
  ngx_stream_set_ctx(s, ctx, this_module);
  
  ctx->build_response = NULL;
  ctx->parse_request = parse_handshake;
  ctx->len = 0;
  
  ngx_stream_cleanup_t* cln = ngx_stream_cleanup_add(s);
  cln->handler = ngx_stream_cleanup_event;
  cln->data = &ctx->timer;
}

static ngx_stream_request_t* parse_handshake(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  lencontent_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_log_t* log = s->connection->log;
  
  ssize_t re = c->recv(c, ctx->temp_buffer+ctx->len, 6-ctx->len);
  if (re <= 0 && re != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (re == NGX_AGAIN) {
    ngx_add_timer(c->read, wscf->handshake_timeout);
    return NULL;
  }
  
  ctx->len += re;
  
  if (ctx->len > 6) {
    ngx_log_error(NGX_LOG_ERR, log, 0
                  , "handshake len more than 6, which is %d", ctx->len);
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (ctx->len < 6) {
    ngx_add_timer(c->read, wscf->handshake_timeout);
    return NULL;
  }
  
  u_char xor = 0;
  for (int i = 0; i < 6; ++i) {
    xor ^= ctx->temp_buffer[i];
  }
  
  if (xor != 0xff) {
    ngx_log_error(NGX_LOG_ERR, log, 0
                  , "handshake xor is not 0xff, which is %d", xor);
    return NGX_STREAM_REQUEST_ERROR;
  }
  
  init_parse_request(s);
  
  return NULL;
}

typedef enum{
  HEART_BEAT,
  DATA
} request_type;

typedef struct{
  request_type type;
  ngx_uint_t  reqid;
} request_ctx;

static void timer_heartbeat_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_session_t* s = c->data;
  ngx_stream_request_t* r = ngx_stream_new_request(s);
  
  ngx_log_debug1(NGX_LOG_DEBUG_STREAM, e->log, 0, "send heartbeat <r=%p>", r);
  
  request_ctx* extra = ngx_pcalloc(r->pool, sizeof(request_ctx));
  extra->type = HEART_BEAT;
  ngx_stream_request_set_ctx(r, extra, this_module);
  handle_request_done(r);

  lencontent_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_add_timer(&ctx->timer, wscf->heartbeat);
}

static ngx_stream_request_t* parse_length(ngx_stream_session_t* s);
static ngx_stream_request_t* parse_data(ngx_stream_session_t* s);

static void init_parse_request(ngx_stream_session_t* s) {
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  lencontent_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_connection_t* c = s->connection;
  
  if (c->read->timer_set) {
    ngx_del_timer(c->read);
  }
  ngx_add_timer(c->read, 2*wscf->heartbeat);
  
  ctx->timer.handler = timer_heartbeat_handler;
  ctx->timer.data = c;
  ctx->timer.log = c->log;
  ngx_add_timer(&ctx->timer, wscf->heartbeat);
  
  ctx->build_response = build_response;
  ctx->parse_request = parse_request;
  ctx->len = 0;
  
  ctx->handler = parse_length;
}

static ngx_stream_request_t* parse_length(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  lencontent_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_log_t* log = s->connection->log;
  
  ssize_t re = c->recv(c, ctx->temp_buffer+ctx->len, 4-ctx->len);
  if (re <= 0 && re != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (re == NGX_AGAIN) {
    ngx_add_timer(c->read, wscf->request_timeout);
    return REQUEST_AGAIN;
  }
  
  ctx->len += re;
  
  if (ctx->len < 4) {
    ngx_add_timer(c->read, wscf->request_timeout);
    return REQUEST_AGAIN;
  }
  
  ngx_int_t len = ntohl(*(uint32_t*)ctx->temp_buffer);
  ctx->len = 0;
  
  if (len == 0) { // heartbeat
    if (c->read->timer_set) {
      ngx_del_timer(c->read);
    }
    ngx_add_timer(c->read, 2*wscf->heartbeat);
    ngx_log_error(NGX_LOG_INFO, log, 0, "receive heartbeat");
    return REQUEST_AGAIN;
  }
  
  if (len <= 4) {
    ngx_log_error(NGX_LOG_ERR, log, 0, "request length <= 4, which is %d", len);
    return NGX_STREAM_REQUEST_ERROR;
  }

  len -= 4;
  
  ctx->r = ngx_stream_new_request(s);
  request_ctx* extra = ngx_pcalloc(ctx->r->pool, sizeof(request_ctx));
  extra->type = DATA;
  ngx_stream_request_set_ctx(ctx->r, extra, this_module);
  ctx->r->data = ngx_pcalloc(ctx->r->pool, sizeof(ngx_chain_t));
  ctx->r->data->buf = ngx_create_temp_buf(ctx->r->pool, len);
  
  ctx->handler = parse_data;
  return REQUEST_DONE;
}

static ngx_stream_request_t* parse_data(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  lencontent_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
//  ngx_log_t* log = s->connection->log;
  ngx_stream_request_t* r = ctx->r;
  
  ssize_t re = c->recv(c, r->data->buf->last, r->data->buf->end - r->data->buf->last);
  if (re <= 0 && re != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (re == NGX_AGAIN) {
    ngx_add_timer(c->read, wscf->request_timeout);
    return REQUEST_AGAIN;
  }
  
  r->data->buf->last += re;
  
  if (r->data->buf->end != r->data->buf->last) {
    ngx_add_timer(c->read, wscf->request_timeout);
    return REQUEST_AGAIN;
  }
  
  ctx->handler = parse_length;
  
  if (c->read->timer_set) {
    ngx_del_timer(c->read);
  }
  ngx_add_timer(c->read, 2*wscf->heartbeat);
  return r;
}

static ngx_stream_request_t* parse_request(ngx_stream_session_t* s) {
  lencontent_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_stream_request_t* r = NULL;
  do {
    r = ctx->handler(s);
  } while (r == REQUEST_DONE);
  if (r == REQUEST_AGAIN) {
    return NULL;
  }
  if (r == NGX_STREAM_REQUEST_ERROR) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  
  ctx->r = NULL;
  
  if (ngx_stream_request_parse_content_protocol(r) == NGX_ERROR) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  
  return r;
}

static void build_head(ngx_stream_request_t* r) {
  ngx_int_t len = ngx_chain_len(r->data) + 4;
  ngx_chain_t* ch = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  ch->buf = ngx_create_temp_buf(r->pool, 4);
  *(u_int32_t*)ch->buf->last = htonl((u_int32_t)len);
  ch->buf->last += 4;
  ch->next = r->data;
  r->data = ch;
}

static void build_response(ngx_stream_request_t* r) {
  request_ctx* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  /**
   * 如果r_ctx == NULL, 则说明r 可能是由其他模块创建，这里补充创建r_ctx
   */
  if (r_ctx == NULL) {
    r_ctx = ngx_pcalloc(r->pool, sizeof(request_ctx));
    ngx_stream_request_set_ctx(r, r_ctx, this_module);
    r_ctx->type = DATA;
  }
  
  switch (r_ctx->type) {
    case HEART_BEAT:
      r->data->buf = ngx_create_temp_buf(r->pool, 4); // set 0
      ngx_memzero(r->data->buf->pos, 4);
      ngx_log_debug5(NGX_LOG_DEBUG_STREAM, r->session->connection->log
                     , 0, "session<%p> build lencontent heartbeat %d %d %d %d"
                     , r->session
                     , r->data->buf->pos[0], r->data->buf->pos[1]
                     , r->data->buf->pos[2], r->data->buf->pos[3]);
      
      r->data->next = NULL;
      r->data->buf->last += 4;
      break;
    default: // DATA
      ngx_stream_request_build_content_protocol(r);
      build_head(r);
      break;
  }

}



