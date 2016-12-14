//
//  ngx_stream_request_websocket_module.c
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/9.
//  Copyright © 2016年 xpwu. All rights reserved.
//

/**
 *  content protocol:
 *  request ---
 *    reqid | data
 *      reqid: 4 bytes, net order;
 *
 *  response ---
 *    reqid | status | data
 *      reqid: 4 bytes, net order;
 *      status: 1 byte, 0---success, 1---failed
 *      data: if status==success, data=<app data>
 *            if status==failed, data=<error reason>
 *
 *
 *  最新协议以 ngx_stream_request_content_logic.h 为准
 *
 */

#define NGX_STREAM_SSL 0

#include "ngx_stream_request_core_module.h"
#include "ngx_stream_request_content_logic.h"
#include "ngx_stream_util.h"
#if (NGX_STREAM_SSL)
#include "ngx_stream_encrypt_module.h"
#endif
#include <ngx_sha1.h>

#define PROTOCOL_RESPONSE_SUCCESS 0
#define PROTOCOL_RESPONSE_FAILED 1

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_websocket_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

static void *ngx_stream_websocket_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_websocket_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child);
char *websocket_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct websocket_srv_conf_s {
  ngx_array_t*  access_origins;
  
  ngx_flag_t  enc; // 是否开启加密
}websocket_srv_conf_t;


static ngx_command_t  ngx_stream_websocket_commands[] = {
  
  { ngx_string("websocket_protocol"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1|NGX_CONF_NOARGS,
    websocket_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  { ngx_string("ws_access_origins"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(websocket_srv_conf_t, access_origins),
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


ngx_module_t  ngx_stream_request_websocket_module = {
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

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - conf
#endif

static void *ngx_stream_websocket_create_srv_conf(ngx_conf_t *cf) {
  websocket_srv_conf_t  *wscf;
  
  wscf = ngx_pcalloc(cf->pool, sizeof(websocket_srv_conf_t));
  if (wscf == NULL) {
    return NULL;
  }
  
  /*
   * set by ngx_pcalloc():
   *    wscf->enc = 0;
   */
  
  wscf->access_origins = NGX_CONF_UNSET_PTR;
  
  return wscf;
}

static char *ngx_stream_websocket_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child) {
  websocket_srv_conf_t *prev = parent;
  websocket_srv_conf_t *conf = child;
  
  ngx_conf_merge_ptr_value(conf->access_origins, prev->access_origins, NULL);
  
  return NGX_CONF_OK;
}

static ngx_int_t verify_access_orign(ngx_stream_session_t* s, ngx_str_t orign) {
  websocket_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  if (wscf->access_origins == NULL) {
    return 1;
  }
  ngx_str_t* access = wscf->access_origins->elts;
  ngx_uint_t num = wscf->access_origins->nelts;
  
  if (num == 0) {
    return 1;
  }
  ngx_uint_t i = 0;
	for (i = 0; i < num; ++i) {
    if (access[i].len == 3 && ngx_memcmp(access[i].data, "all", 3) == 0) {
      return 1;
    }
    if (access[i].len == orign.len
        && ngx_memcmp(access[i].data, orign.data, 3) == 0) {
      return 1;
    }
  }
  return 0;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - http error
#endif

static void http_501(ngx_buf_t* buf) {
  ngx_str_t temp = ngx_string("HTTP/1.1 501 Not implemented");
  ngx_memcpy(buf->last, temp.data, temp.len);
  buf->last += temp.len;
  *buf->last++ = CR;
  *buf->last++ = LF;
  *buf->last++ = CR;
  *buf->last++ = LF;
}

static void http_408(ngx_buf_t* buf) {
  ngx_str_t temp = ngx_string("HTTP/1.1 408 Request Timeout");
  ngx_memcpy(buf->last, temp.data, temp.len);
  buf->last += temp.len;
  *buf->last++ = CR;
  *buf->last++ = LF;
  *buf->last++ = CR;
  *buf->last++ = LF;
}

static void http_403(ngx_buf_t* buf) {
  ngx_str_t temp = ngx_string("HTTP/1.1 403 Forbidden");
  ngx_memcpy(buf->last, temp.data, temp.len);
  buf->last += temp.len;
  *buf->last++ = CR;
  *buf->last++ = LF;
  *buf->last++ = CR;
  *buf->last++ = LF;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - handshake
#endif

static void init_parse(ngx_stream_session_t* s);

static ngx_stream_request_t* parse_handshake(ngx_stream_session_t*);
static void build_handshake(ngx_stream_request_t* r);

static void init_parse_request(ngx_stream_session_t* s);
static ngx_stream_request_t* parse_request(ngx_stream_session_t*);
static void build_response(ngx_stream_request_t* r);

#if (NGX_STREAM_SSL)
static void init_enc_handshake(ngx_stream_session_t* s);
static ngx_stream_request_t* parse_enc_handshake(ngx_stream_session_t*);
static void build_enc_handshake(ngx_stream_request_t* r);
#endif

#define REQUEST_AGAIN (ngx_stream_request_t*) NGX_AGAIN
#define REQUEST_DONE (ngx_stream_request_t*) NGX_DONE
/*  return ngx_stream_request_t*: 解析到一个request
 return REQUEST_AGAIN: 解析数据不够
 return REQUEST_DONE: 进行下一步
 */
typedef ngx_stream_request_t* (*request_handler_t)(ngx_stream_session_t*);

static ngx_stream_request_t* parse_request_handler (ngx_stream_session_t* s);
static void build_response_handler(ngx_stream_request_t* r);

char *websocket_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  websocket_srv_conf_t  *wscf = conf;
  ngx_str_t* value = cf->args->elts;
  if (cf->args->nelts == 2) {
    if (value[1].len != 3 || ngx_memcmp(value[1].data, "enc", 3) != 0) {
      return "args is 'enc' only";
    }
#if (!NGX_STREAM_SSL)
    return "'enc' must define NGX_STREAM_SSL";
#endif
    wscf->enc = 1;
  }
  
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  cscf->init_parser = init_parse;
  cscf->build_response = build_response_handler;
  cscf->parse_request = parse_request_handler;
  
  return NGX_CONF_OK;
}

typedef struct{
  ngx_uint_t sec_websocket_version;
  ngx_str_t sec_websocket_key;
  ngx_str_t origin;
  ngx_int_t first_line;
  ngx_int_t last_is_crlf;
  ngx_str_t host;
  ngx_pool_t* pool;
  ngx_stream_request_t* r;
} handshake_ctx_t;

typedef struct{
  ngx_int_t fin;
  ngx_int_t opcode;
  u_char mask[4];
  ngx_int_t length;
} websocket_frame_head_t;

typedef struct {
  handshake_ctx_t* handshake_ctx;
  ngx_event_t timer;
  
  ngx_buf_t* recv_buffer; // 与session 同生命
  // 数据帧中可能会插入控制帧
  ngx_stream_request_t* r;
  ngx_stream_request_t* tmp_controller_r;
  websocket_frame_head_t* head;
  
  request_handler_t handler;
  
  ngx_stream_request_t* (*parse_request)(ngx_stream_session_t*);
  void (*build_response)(ngx_stream_request_t*);
} websocket_ctx_t;

static ngx_stream_request_t* parse_request_handler (ngx_stream_session_t* s) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  return ctx->parse_request(s);
}

static void build_response_handler(ngx_stream_request_t* r) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(r->session, this_module);
  ctx->build_response(r);
}

static void timer_handshake_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_session_t* s = c->data;
  if (e->timedout) {
    ngx_buf_t* temp = ngx_create_temp_buf(c->pool, 1024);
    http_408(temp);
    c->send(c, temp->pos, temp->last-temp->pos);
    ngx_stream_finalize_session_r(s, "websocket timeout");
  }
}

static void ngx_stream_cleanup_event(void *data) {
  ngx_event_t* timer = data;
  
  if (timer->timer_set) {
    ngx_del_timer(timer);
  }
}

static void init_parse(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
    = ngx_stream_get_module_srv_conf(s, core_module);
  
  websocket_ctx_t* ctx = ngx_pcalloc(c->pool, sizeof(websocket_ctx_t));
  ngx_stream_request_t* r = ngx_stream_new_request(s);
  ctx->handshake_ctx = ngx_pcalloc(r->pool, sizeof(handshake_ctx_t));
  ctx->handshake_ctx->pool = r->pool;
  ctx->handshake_ctx->sec_websocket_version = (ngx_uint_t)(-1);
  ctx->handshake_ctx->first_line = 1;
  ctx->handshake_ctx->last_is_crlf = 0;
  ctx->handshake_ctx->r = r;
  
  ctx->recv_buffer = ngx_create_temp_buf(s->connection->pool, 1024);
  
  ctx->timer.handler = timer_handshake_handler;
  ctx->timer.data = c;
  ctx->timer.log = c->log;
  ngx_add_timer(&ctx->timer, cscf->handshake_timeout);
  
  ngx_stream_set_ctx(s, ctx, this_module);
  
  ctx->build_response = build_handshake;
  ctx->parse_request = parse_handshake;
  
  ngx_stream_cleanup_t* cln = ngx_stream_cleanup_add(s);
  cln->handler = ngx_stream_cleanup_event;
  cln->data = &ctx->timer;
}

static ngx_int_t parse_handshake_req(ngx_buf_t* buf, handshake_ctx_t* ctx) {
  ngx_int_t end_head = 0;
  u_char* p = NULL;
	for (p = buf->pos; p+1 < buf->last; ++p) {
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
      if (ngx_strcmp(p1, "Host") == 0) {
        ctx->host.len = p-p3;
        ctx->host.data = ngx_pcalloc(ctx->pool, p-p3);
        ngx_memcpy(ctx->host.data, p3, p-p3);
      }
      p = buf->pos - 1;
    }
  }
  
  return end_head == 1 ? NGX_OK : NGX_AGAIN;
}

static ngx_stream_request_t* parse_handshake(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  handshake_ctx_t* handshake_ctx = ctx->handshake_ctx;
  ngx_log_t* log = s->connection->log;
  
  if (ctx->timer.timer_set) {
    ngx_del_timer(&ctx->timer);
  }
  
  ssize_t re = c->recv(c, ctx->recv_buffer->last
                       , ctx->recv_buffer->end - ctx->recv_buffer->last);
  
  if (re <= 0 && re != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (re == NGX_AGAIN) {
    ngx_add_timer(&ctx->timer, cscf->handshake_timeout);
    return NULL;
  }
  
  ngx_log_error(NGX_LOG_INFO, log, 0, "%*s", re, ctx->recv_buffer->last);
  ctx->recv_buffer->last += re;
  
  ngx_int_t result = parse_handshake_req(ctx->recv_buffer, handshake_ctx);
  if (result == NGX_ERROR) {
    ngx_log_error(NGX_LOG_ERR, log, 0, ", websocket handshake error");
    return NGX_STREAM_REQUEST_ERROR;
  }
  ngx_regular_buf(ctx->recv_buffer);
  
  if (result == NGX_AGAIN) {
    ngx_add_timer(&ctx->timer, cscf->handshake_timeout);
    return NULL;
  }
  
  if (handshake_ctx->sec_websocket_version != 13) {
    ngx_log_error(NGX_LOG_ERR, log, 0, ", websocket handshake version is not 13");
    ngx_buf_t* temp = ngx_create_temp_buf(c->pool, 1024);
    http_501(temp);
    c->send(c, temp->pos, temp->last-temp->pos);
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (verify_access_orign(s, handshake_ctx->origin) != 1) {
    ngx_log_error(NGX_LOG_ERR, log, 0, ", origin(%V) is not access"
                  , &handshake_ctx->origin);
    ngx_buf_t* temp = ngx_create_temp_buf(c->pool, 1024);
    http_403(temp);
    c->send(c, temp->pos, temp->last-temp->pos);
    return NGX_STREAM_REQUEST_ERROR;
  }
  
  ngx_stream_request_t* r = handshake_ctx->r;
  r->data->buf = ngx_create_temp_buf(r->pool, 1000);
  ngx_memcpy(r->data->buf->last, handshake_ctx->sec_websocket_key.data
             , handshake_ctx->sec_websocket_key.len);
  r->data->buf->last += handshake_ctx->sec_websocket_key.len;
  
  handle_request_done(r);
  
  return NULL; // handshake always return null
}

static void build_handshake(ngx_stream_request_t* r) {
  ngx_buf_t* buf = ngx_create_temp_buf(r->pool, 500);
  ngx_buf_t* oribuf = r->data->buf;
  char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  ngx_sha1_t sha_ctx;
  ngx_sha1_init(&sha_ctx);
  ngx_sha1_update(&sha_ctx, oribuf->pos, oribuf->last-oribuf->pos);
  ngx_sha1_update(&sha_ctx, guid, sizeof(guid)-1);
  ngx_str_t sha1;
  sha1.len = SHA_DIGEST_LENGTH;
  sha1.data = ngx_pcalloc(r->pool, SHA_DIGEST_LENGTH);
  ngx_sha1_final(sha1.data, &sha_ctx);
  ngx_str_t base64;
  base64.len = ngx_base64_encoded_length(SHA_DIGEST_LENGTH);
  base64.data = ngx_pcalloc(r->pool, base64.len);
  ngx_encode_base64(&base64, &sha1);
  
  ngx_str_t temp = ngx_string("HTTP/1.1 101 Switching Protocols");
  ngx_memcpy(buf->last, temp.data, temp.len);
  buf->last += temp.len;
  *buf->last++ = CR;
  *buf->last++ = LF;
  ngx_str_t temp2 = ngx_string("Upgrade: websocket");
  ngx_memcpy(buf->last, temp2.data, temp2.len);
  buf->last += temp2.len;
  *buf->last++ = CR;
  *buf->last++ = LF;
  ngx_str_t temp3 = ngx_string("Connection: Upgrade");
  ngx_memcpy(buf->last, temp3.data, temp3.len);
  buf->last += temp3.len;
  *buf->last++ = CR;
  *buf->last++ = LF;
  ngx_str_t temp4 = ngx_string("Sec-WebSocket-Accept: ");
  ngx_memcpy(buf->last, temp4.data, temp4.len);
  buf->last += temp4.len;
  ngx_memcpy(buf->last, base64.data, base64.len);
  buf->last += base64.len;
  
  *buf->last++ = CR;
  *buf->last++ = LF;
  
  *buf->last++ = CR;
  *buf->last++ = LF;
  
  r->data->buf = buf;
  r->data->next = NULL;
  
#if (NGX_STREAM_SSL)
  init_enc_handshake(r->session);
#else
  init_parse_request(r->session);
#endif
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - request
#endif

#ifndef ntohll
#ifdef NGX_HAVE_LITTLE_ENDIAN
#define ntohll(n) ((uint64_t)ntohl(n) << 32) + (ntohl(n >> 32))
#else
#define ntohll(n) n
#endif
#endif

#ifndef htonll
#ifdef NGX_HAVE_LITTLE_ENDIAN
#define htonll(n) ((uint64_t)htonl(n) << 32) + (htonl(n >> 32))
#else
#define htonll(n) n
#endif
#endif

static ngx_stream_request_t* parse_head(ngx_stream_session_t*);
static ngx_stream_request_t* parse_length126(ngx_stream_session_t*);
static ngx_stream_request_t* parse_length127(ngx_stream_session_t*);
static ngx_stream_request_t* parse_mask(ngx_stream_session_t*);
static ngx_stream_request_t* parse_data(ngx_stream_session_t*);

typedef enum{
  PING, // 回应ping
  PONG, // 回应 pong
  CLOSE,
  BINARY,
  NO_RESPONSE
} request_type;

typedef struct{
  request_type type;
} request_ctx;

static void timer_heartbeat_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_session_t* s = c->data;
  ngx_stream_request_t* r = ngx_stream_new_request(s);
  
  ngx_log_debug1(NGX_LOG_DEBUG_STREAM, e->log, 0, "send ping response<r=%p>", r);
  
  request_ctx* extra = ngx_pcalloc(r->pool, sizeof(request_ctx));
  extra->type = PING;
  ngx_stream_request_set_ctx(r, extra, this_module);
  handle_request_done(r);
  
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_add_timer(&ctx->timer, cscf->heartbeat);
}

static void init_parse_request(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ctx->build_response = build_response;
  ctx->parse_request = parse_request;
  
  ctx->timer.handler = timer_heartbeat_handler;
  ngx_add_timer(&ctx->timer, cscf->heartbeat);
  
  if (c->read->timer_set) {
    ngx_del_timer(c->read);
  }
  ngx_add_timer(c->read, 2*cscf->heartbeat);
  
  if (ctx->head == NULL) {
    ctx->head = ngx_pcalloc(c->pool, sizeof(websocket_frame_head_t));
  }
  ctx->handler = parse_head;
  ctx->r = NULL;
  ctx->tmp_controller_r = NULL;
  
  ngx_regular_buf(ctx->recv_buffer);
}

static void build_websocket_v13_close(ngx_connection_t* c, ngx_uint_t close_code) {
  u_char buf[4];
  buf[0] = 0x88;
  buf[1] = 0x02;
  *((uint16_t*)buf+2) = htons(close_code);
  c->send(c, buf, 4);
}

static ngx_stream_request_t* parse_request(ngx_stream_session_t* s) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
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
  
  if (r == ctx->r) {
    ctx->r = NULL;
  } else if (r == ctx->tmp_controller_r) {
    ctx->tmp_controller_r = NULL;
  } else {
    r = NGX_STREAM_REQUEST_ERROR;
  }
  
  if ((ctx->head->opcode & 0x08) != 0) {
    return r;
  }
  
  
//#if (NGX_STREAM_SSL)
//  websocket_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
//  if (wscf->enc) {
//    ngx_buf_t* tmp_buffer = r->data->buf;
//    ngx_uint_t len = tmp_buffer->last - tmp_buffer->pos;
//    ngx_pool_t* tmp_pool = NULL;
//    if (r->data->next != NULL) {
//      len = ngx_chain_len(r->data);
//      tmp_pool = ngx_create_pool(len + 500, s->connection->log);
//      tmp_buffer = ngx_create_temp_buf(tmp_pool, len);
//      
//      for (ngx_chain_t* ch = r->data; ch != NULL; ch = ch->next) {
//        ngx_uint_t this_len = ch->buf->last - ch->buf->pos;
//        ngx_memcpy(tmp_buffer->last, ch->buf->pos, this_len);
//        tmp_buffer->last += len;
//      }
//    }
//    ngx_buf_t* out = ngx_create_temp_buf(r->pool, ngx_stream_decrypt_max_size(len));
//    ngx_int_t rc = ngx_stream_decrypt_buffer(s, tmp_buffer, out);
//    if (rc == NGX_ERROR) {
//      return NGX_STREAM_REQUEST_ERROR;
//    }
//    if (tmp_pool != NULL) {
//      ngx_destroy_pool(tmp_pool);
//    }
//    
//    r->data->buf = out;
//    r->data->next = NULL;
//  }
//#endif
  
  if (ngx_stream_request_parse_content_protocol(r) == NGX_ERROR) {
    return NGX_STREAM_REQUEST_ERROR;
  }

  return r;
}

static void build_websocket_v13_head(ngx_stream_request_t* r
                                     , uint8_t first_code) {
  ngx_chain_t* head = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  head->buf = ngx_create_temp_buf(r->pool, 20);
  head->buf->last[0] = first_code;
  head->buf->last++;
  ngx_int_t length = ngx_chain_len(r->data);
  
  if (length <= 125) {
    head->buf->last[0] = (uint8_t)length;
    head->buf->last++;
  } else if (length < 65536) {
    head->buf->last[0] = 126;
    head->buf->last++;
    *((uint16_t*)head->buf->last) = htons(length);
    head->buf->last += 2;
  } else {
    head->buf->last[0] = 127;
    head->buf->last++;
    *((uint64_t*)head->buf->last) = htonll(length);
    head->buf->last += 8;
  }
  
  head->next = r->data;
  r->data = head;
}

//static void enc_data(ngx_stream_request_t* r) {
//#if (NGX_STREAM_SSL)
//  ngx_stream_session_t* s = r->session;
//  websocket_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);
//  if (wscf->enc) {
//    ngx_buf_t* tmp_buffer = r->data->buf;
//    ngx_uint_t len = tmp_buffer->last - tmp_buffer->pos;
//    ngx_pool_t* tmp_pool = NULL;
//    if (r->data->next != NULL) {
//      len = ngx_chain_len(r->data);
//      tmp_pool = ngx_create_pool(len + 500, s->connection->log);
//      tmp_buffer = ngx_create_temp_buf(tmp_pool, len);
//      
//      for (ngx_chain_t* ch = r->data; ch != NULL; ch = ch->next) {
//        ngx_uint_t this_len = ch->buf->last - ch->buf->pos;
//        ngx_memcpy(tmp_buffer->last, ch->buf->pos, this_len);
//        tmp_buffer->last += len;
//      }
//    }
//    ngx_buf_t* out = ngx_create_temp_buf(r->pool, ngx_stream_encrypt_size(len));
//    ngx_int_t rc = ngx_stream_encrypt_buffer(s, tmp_buffer, out);
//    if (rc == NGX_ERROR) {
//      return;
//    }
//    if (tmp_pool != NULL) {
//      ngx_destroy_pool(tmp_pool);
//    }
//    
//    r->data->buf = out;
//    r->data->next = NULL;
//  }
//#endif
//}

static void build_response(ngx_stream_request_t* r) {
  request_ctx* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  /**
   * 如果r_ctx == NULL, 则说明r 可能是由其他模块创建，这里补充创建r_ctx
   */
  if (r_ctx == NULL) {
    r_ctx = ngx_pcalloc(r->pool, sizeof(request_ctx));
    ngx_stream_request_set_ctx(r, r_ctx, this_module);
    r_ctx->type = BINARY;
  }
  
  switch (r_ctx->type) {
    case PING:
      r->data->buf = ngx_create_temp_buf(r->pool, 2);
      r->data->next = NULL;
      r->data->buf->last[0] = 0x89;
      r->data->buf->last[1] = 0x00;
      r->data->buf->last += 2;
      break;
    case PONG:
      build_websocket_v13_head(r, 0x8a);
      break;
    case NO_RESPONSE:
      r->data = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      r->data->buf = ngx_create_temp_buf(r->pool, 1);
      break;
    case CLOSE: // noting
      break;
    default: // BINARY
      ngx_stream_request_build_content_protocol(r);
      build_websocket_v13_head(r, 0x82);
      break;
  }
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - parse data
#endif

static ngx_stream_request_t* read_buffer(ngx_stream_session_t* s, ngx_uint_t cnt) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ssize_t n = c->recv(c, ctx->recv_buffer->last
                      , cnt - (ctx->recv_buffer->last-ctx->recv_buffer->pos));
  if (n <= 0 && n != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (n == NGX_AGAIN) {
    ngx_add_timer(c->read, cscf->request_timeout);
    return REQUEST_AGAIN;
  }
  ctx->recv_buffer->last += n;
  if (ctx->recv_buffer->last - ctx->recv_buffer->pos < (ssize_t)cnt) {
    ngx_add_timer(c->read, cscf->request_timeout);
    return REQUEST_AGAIN;
  }
  return REQUEST_DONE;
}

static ngx_stream_request_t* parse_head(ngx_stream_session_t* s) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  
  ngx_stream_request_t* r = read_buffer(s, 2);
  
  // 实际使用中，部分事件模型对ready的状态改变有延时性，故这里再加一层判断
  // 此处没有考虑 连续多帧才发送完数据包的情况
  if (r == REQUEST_AGAIN) {
    if (ctx->recv_buffer->last - ctx->recv_buffer->pos == 0) {
      if (c->read->timer_set) {
        ngx_del_timer(c->read);
      }
      ngx_add_timer(c->read, 2*cscf->heartbeat);
    }
  }
  
  if (r != REQUEST_DONE) {
    return r;
  }
  
  websocket_frame_head_t* frame = ctx->head;
  ngx_buf_t* buffer = ctx->recv_buffer;
  frame->fin = *buffer->pos & 0x80;
  frame->opcode = *buffer->pos & 0x0f;
  buffer->pos ++;
  ngx_int_t len = *buffer->pos & 0x7f;
  buffer->pos ++;
  if (len == 126) {
    ctx->handler = parse_length126;
  } else if (len == 127) {
    ctx->handler = parse_length127;
  } else {
    frame->length = len;
    ctx->handler = parse_mask;
  }
  return REQUEST_DONE;
}

static ngx_stream_request_t* parse_length126(ngx_stream_session_t* s) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_stream_request_t* r = read_buffer(s, 2);
  if (r != REQUEST_DONE) {
    return r;
  }
  
  uint16_t len = *(uint16_t*)ctx->recv_buffer->pos;
  ctx->recv_buffer->pos += 2;
  len = ntohs(len);
  ctx->head->length = len;
  ctx->handler = parse_mask;
  return REQUEST_DONE;
}

static ngx_stream_request_t* parse_length127(ngx_stream_session_t* s) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_stream_request_t* r = read_buffer(s, 8);
  if (r != REQUEST_DONE) {
    return r;
  }
  
  int64_t len = *(int64_t*)ctx->recv_buffer->pos;
  ctx->recv_buffer->pos += 8;
  len = ntohll(len);
  ctx->head->length = len;
  ctx->handler = parse_mask;
  return REQUEST_DONE;
}

static ngx_stream_request_t* parse_mask(ngx_stream_session_t* s) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_stream_request_t* r = read_buffer(s, 4);
  if (r != REQUEST_DONE) {
    return r;
  }
  
  ngx_memcpy(ctx->head->mask, ctx->recv_buffer->pos, 4);
  ctx->recv_buffer->pos += 4;
  ngx_regular_buf(ctx->recv_buffer);
  
  ctx->handler = parse_data;
  // init parse_data
  if ((ctx->head->opcode & 0x08) == 0) { // 数据帧
    if (ctx->r == NULL) {
      ctx->r = ngx_stream_new_request(s);
    }
    r = ctx->r;
  } else {
    if (ctx->tmp_controller_r == NULL) {
      ctx->tmp_controller_r = ngx_stream_new_request(s);
    }
    r = ctx->tmp_controller_r;
  }
  ngx_chain_t* last = r->data;
  while (last->next != NULL) {
    last = last->next;
  }
  last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  last = last->next;
  ngx_int_t fake_len = ctx->head->length != 0? ctx->head->length: 1;
  last->buf = ngx_create_temp_buf(r->pool, fake_len);

  return REQUEST_DONE;
}

static ngx_int_t read_data_to_r(ngx_stream_request_t* r) {
  ngx_stream_session_t* s = r->session;
  ngx_connection_t* c = s->connection;
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_int_t len = ctx->head->length;
  
  if (len == 0) {
    return NGX_OK;
  }
  ngx_chain_t* last = r->data;
  while (last->next != NULL) {
    last = last->next;
  }
  
  len = last->buf->end - last->buf->last;
  ssize_t n = c->recv(c, last->buf->last, len);
  if (n == NGX_AGAIN) {
    return NGX_AGAIN;
  }
  if (n <= 0) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "read_data_to_r error");
    return NGX_ERROR;
  }
  last->buf->last += n;
  if (last->buf->last != last->buf->end) {
    return NGX_AGAIN;
  }
  
  ngx_int_t i = 0;
	for (i = 0; i < last->buf->last - last->buf->pos; ++i) {
    last->buf->pos[i] ^= ctx->head->mask[i%4];
  }
  
  return NGX_OK;
}

static ngx_stream_request_t* parse_data(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_core_srv_conf_t* cscf
  = ngx_stream_get_module_srv_conf(s, core_module);
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_stream_request_t* r = NULL;
  if ((ctx->head->opcode & 0x08) == 0) { // 数据帧
    r = ctx->r;
  } else {
    r = ctx->tmp_controller_r;
  }
  
  ngx_int_t re = read_data_to_r(r);
  if (re == NGX_ERROR) {
    return NGX_STREAM_REQUEST_ERROR;
  } else if (re == NGX_AGAIN) {
    ngx_add_timer(c->read, cscf->request_timeout);
    return REQUEST_AGAIN;
  }
  
  ctx->handler = parse_head;
  
  if (ctx->head->fin == 0) { //不是最后一帧
    ngx_add_timer(c->read, cscf->request_timeout);
    return REQUEST_AGAIN;
  }
  
  if (ctx->head->opcode == 8) { // close
    ngx_int_t cd = 0;
    
    // 为了加快速度，由前面的解析可知：r->data->next->buf 才是真正的数据
    // 直接hardcode 到r->data->next->buf
    ngx_buf_t* buf = r->data->next->buf;
    if (buf->pos + 2 < buf->last) {
      cd = ntohs(*((uint16_t*)buf->pos));
      buf->pos += 2;
    }
    ngx_int_t len = buf->last - buf->pos + 50;
    u_char reason[len];
    ngx_memzero(reason, len);
    ngx_sprintf(reason, "closed by client!---code=%d %s"
                , cd, buf->pos);
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0
                  , ", connection closed because %s", reason);
    build_websocket_v13_close(c, 1000);
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (ctx->head->opcode == 10) { // pong
    if (ctx->tmp_controller_r) {
      ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "received pong frame");
      request_ctx* r_ctx = ngx_pcalloc(r->pool, sizeof(request_ctx));
      r_ctx->type = NO_RESPONSE;
      ngx_stream_request_set_ctx(r, r_ctx, this_module);
      handle_request_done(r);
      ctx->tmp_controller_r = NULL;
    }
    if (c->read->timer_set) {
      ngx_del_timer(c->read);
    }
    ngx_add_timer(c->read, 2*cscf->heartbeat);
    return REQUEST_AGAIN;
  }
  if (ctx->head->opcode == 9) { // ping
    request_ctx* extra = ngx_pcalloc(r->pool, sizeof(request_ctx));
    extra->type = PONG;
    ngx_stream_request_set_ctx(r, extra, this_module);
  }
  if ((ctx->head->opcode & 0x08) == 0) {
    request_ctx* r_ctx = ngx_pcalloc(r->pool, sizeof(request_ctx));
    r_ctx->type = BINARY;
    ngx_stream_request_set_ctx(r, r_ctx, this_module);
  }
  
  if (c->read->timer_set) {
    ngx_del_timer(c->read);
  }
  ngx_add_timer(c->read, 2*cscf->heartbeat);
  return r;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - enc
#endif

#if (NGX_STREAM_SSL)
static void init_enc_handshake(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  websocket_srv_conf_t* wscf = ngx_stream_get_module_srv_conf(s, this_module);

  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ctx->build_response = build_enc_handshake;
  ctx->parse_request = parse_enc_handshake;
  
  if (c->read->timer_set) {
    ngx_del_timer(c->read);
  }
  ngx_add_timer(c->read, wscf->handshake_timeout);
  
  if (ctx->head == NULL) {
    ctx->head = ngx_pcalloc(c->pool, sizeof(websocket_frame_head_t));
  }
  ctx->handler = parse_head;
  ctx->r = NULL;
  ctx->tmp_controller_r = NULL;
  
  ngx_regular_buf(ctx->recv_buffer);
}

static ngx_stream_request_t* parse_enc_handshake(ngx_stream_session_t* s) {
  websocket_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
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
  
  if (r == ctx->r) {
    ctx->r = NULL;
  } else if (r == ctx->tmp_controller_r) {
    ctx->tmp_controller_r = NULL;
  } else {
    r = NGX_STREAM_REQUEST_ERROR;
  }
  
  if ((ctx->head->opcode & 0x08) != 0) { // 不是数据
    ngx_stream_close_request(r);
    return NULL;
  }
  
  ngx_buf_t* buffer = ngx_create_temp_buf(r->pool, ngx_stream_encrypt_handshake_size(s));
  for (ngx_chain_t* ch = r->data; ch != NULL; ch = ch->next) {
    ngx_int_t re = ngx_stream_encrypt_handshake(s, ch->buf, buffer);
    if (re == NGX_ERROR) {
      return NGX_STREAM_REQUEST_ERROR;
    }
    if (re == NGX_OK) {
      r->data->buf = buffer;
      r->data->next = NULL;
      handle_request_done(r);
      return NULL;
    }
    // re == NGX_AGAIN, continue
  }
  
  return NULL;
}

static void build_enc_handshake(ngx_stream_request_t* r) {
  build_websocket_v13_head(r, 0x82);
  
  init_parse_request(r->session);
}
#endif

