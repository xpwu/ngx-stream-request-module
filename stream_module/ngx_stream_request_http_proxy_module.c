//
//  ngx_stream_request_http_proxy_module.c
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/9.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include "ngx_stream_request_core_module.h"
#include "ngx_stream_variable_module.h"


#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_http_proxy_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

#pragma mark - list hash
typedef struct ngx_list_hash_elt_s ngx_list_hash_elt_t;
struct ngx_list_hash_elt_s{
  ngx_str_t key;
  ngx_str_t value;
  ngx_list_hash_elt_t* next;
};

typedef struct{
  ngx_list_hash_elt_t** elts;
  u_char size;
} ngx_list_hash_t;

void ngx_list_hash_init(ngx_list_hash_t* hashtable, u_char size
                        , ngx_pool_t* pool) {
  hashtable->size = size;
  hashtable->elts = ngx_pcalloc(pool, hashtable->size*sizeof(ngx_list_hash_elt_t*));
}

void ngx_list_hash_insert(ngx_list_hash_t* hashtable
                          , ngx_list_hash_elt_t* elt) {
  ngx_uint_t key = ngx_hash_key(elt->key.data, elt->key.len);
  key = key % hashtable->size;
  elt->next = hashtable->elts[key];
  hashtable->elts[key] = elt;
}

ngx_str_t* ngx_list_hash_find(ngx_list_hash_t* hashtable, ngx_str_t key) {
  if (hashtable == NULL) {
    return NULL;
  }
  if (key.len == 0) {
    return NULL;
  }
  ngx_uint_t hash = ngx_hash_key(key.data, key.len);
  hash = hash % hashtable->size;
  ngx_list_hash_elt_t* elt = hashtable->elts[hash];
  for (; elt != NULL; elt=elt->next) {
    if (elt->key.len == key.len
        && ngx_memcmp(elt->key.data, key.data, key.len) == 0) {
      return &elt->value;
    }
  }
  return NULL;
}

#pragma mark - conf

static void *ngx_stream_http_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_http_proxy_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child);
char *http_proxy_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
  ngx_array_t* set_header;
  ngx_array_t* set_header_if_empty;
  ngx_array_t* set_session;
  ngx_array_t* set_session_if_empty;
  ngx_list_hash_t* header_if_empty_table;
  ngx_str_t uri;
  
//  ngx_msec_t  send_timeout;
//  ngx_msec_t  receive_timeout;
//  ngx_msec_t  response_timeout;
}http_proxy_srv_conf_t;

typedef struct{
  ngx_list_hash_t* response_header;
  ngx_buf_t* receive_buffer;
  ngx_int_t last_is_crlf;
  
  ngx_int_t (*chunk_data_handler)(ngx_stream_request_t* r);
  ngx_flag_t chunk_is_end;
} http_proxy_ctx_t;

char* set_session_post_handler (ngx_conf_t *cf, void *data, void *conf) {
  ngx_keyval_t* keyval = conf;
  ngx_str_t key = keyval->key;
  if (key.len <= 1 || key.data[0] != '$') {
    return "variable must be ahead of '$'";
  }
  
  ngx_memmove(key.data, key.data+1, key.len-1);
  keyval->key.len -= 1;
  
  return NGX_CONF_OK;
}

static ngx_conf_post_t conf_post = {set_session_post_handler};

static ngx_command_t  ngx_stream_http_proxy_commands[] = {
  
  { ngx_string("http_proxy_pass"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    http_proxy_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
//  { ngx_string("http_proxy_send_timeout"),
//    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
//    ngx_conf_set_msec_slot,
//    NGX_STREAM_SRV_CONF_OFFSET,
//    offsetof(http_proxy_srv_conf_t, send_timeout),
//    NULL},
//  
//  { ngx_string("http_proxy_receive_timeout"),
//    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
//    ngx_conf_set_msec_slot,
//    NGX_STREAM_SRV_CONF_OFFSET,
//    offsetof(http_proxy_srv_conf_t, receive_timeout),
//    NULL},
//  
//  { ngx_string("http_proxy_response_timeout"),
//    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
//    ngx_conf_set_msec_slot,
//    NGX_STREAM_SRV_CONF_OFFSET,
//    offsetof(http_proxy_srv_conf_t, response_timeout),
//    NULL},
  
  { ngx_string("http_proxy_set_uri"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(http_proxy_srv_conf_t, uri),
    NULL},
  
  { ngx_string("http_proxy_set_header"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE23,
    ngx_conf_set_keyval_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(http_proxy_srv_conf_t, set_header),
    NULL},
  
  { ngx_string("http_proxy_set_header_if_empty"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE23,
    ngx_conf_set_keyval_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(http_proxy_srv_conf_t, set_header_if_empty),
    NULL},
  
  { ngx_string("http_proxy_set_session_if_empty"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_keyval_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(http_proxy_srv_conf_t, set_session_if_empty),
    &conf_post},
  
  { ngx_string("http_proxy_set_session"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_keyval_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(http_proxy_srv_conf_t, set_session),
    &conf_post},
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_http_proxy_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  ngx_stream_http_proxy_create_srv_conf,   /* create server configuration */
  ngx_stream_http_proxy_merge_srv_conf     /* merge server configuration */
};


ngx_module_t  ngx_stream_request_http_proxy_module = {
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

#pragma mark - conf impl

static void *ngx_stream_http_proxy_create_srv_conf(ngx_conf_t *cf) {
  http_proxy_srv_conf_t  *pscf;
  
  pscf = ngx_pcalloc(cf->pool, sizeof(http_proxy_srv_conf_t));
  if (pscf == NULL) {
    return NULL;
  }
  
  /*
   * set by ngx_pcalloc():
   *    pscf->set_header = NULL;
   *    pscf->set_header_if_empty = NULL;
   *    pscf->set_session = NULL;
   *    pscf->set_session_if_empty = NULL;
   *    pscf->uri.data = NULL;
   *
   */
  
//  pscf->receive_timeout = NGX_CONF_UNSET_MSEC;
//  pscf->send_timeout = NGX_CONF_UNSET_MSEC;
//  pscf->response_timeout = NGX_CONF_UNSET_MSEC;
  
  return pscf;
}

#define ngx_conf_merge_keyval_value(conf, prev, default)                        \
  if (conf == NULL) {                                        \
    conf = (prev == NULL) ? default : prev;                \
  }

static char *ngx_stream_http_proxy_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child) {
  http_proxy_srv_conf_t *prev = parent;
  http_proxy_srv_conf_t *conf = child;
  
//  ngx_conf_merge_ptr_value(conf->set_header, prev->set_header, NULL);
//  ngx_conf_merge_ptr_value(conf->set_header_if_empty, prev->set_header_if_empty, NULL);
//  ngx_conf_merge_ptr_value(conf->set_session, prev->set_session, NULL);
//  ngx_conf_merge_ptr_value(conf->set_session_if_empty
//                           , prev->set_session_if_empty, NULL);
  /**
   ngx_conf_merge_ptr_value(conf, prev) 要求conf=NGX_CONF_UNSET_PTR 才合并 但是 
   ngx_conf_set_keyval_slot 要求为NULL才能初始化，存在矛盾，因此这里不能使用
   ngx_conf_merge_ptr_value 合并keyval 类型的ngx_array_t
   */
  ngx_conf_merge_keyval_value(conf->set_header, prev->set_header, NULL);
  ngx_conf_merge_keyval_value(conf->set_header_if_empty, prev->set_header_if_empty, NULL);
  ngx_conf_merge_keyval_value(conf->set_session, prev->set_session, NULL);
  ngx_conf_merge_keyval_value(conf->set_session_if_empty
                           , prev->set_session_if_empty, NULL);
  
  ngx_conf_merge_str_value(conf->uri, prev->uri, "/");
  
//  ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 5000);
//  ngx_conf_merge_msec_value(conf->receive_timeout, prev->receive_timeout, 5000);
//  ngx_conf_merge_msec_value(conf->response_timeout, prev->response_timeout, 10000);
  
  ngx_uint_t header_if_empty_len = 0;
  if (conf->set_header_if_empty != NULL) {
    header_if_empty_len = conf->set_header_if_empty->nelts;
  }
  if (header_if_empty_len != 0) {
    conf->header_if_empty_table = ngx_pcalloc(cf->pool
                                              , sizeof(ngx_list_hash_t));
    ngx_list_hash_init(conf->header_if_empty_table
                       , 11, cf->pool);
    ngx_keyval_t* elts = conf->set_header_if_empty->elts;
    for (ngx_uint_t i = 0; i < header_if_empty_len; ++i) {
      ngx_list_hash_elt_t* elt = ngx_pcalloc(cf->pool, sizeof(ngx_list_hash_elt_t));
      elt->key = elts[i].key;
      elt->value = elts[i].value;
      ngx_list_hash_insert(conf->header_if_empty_table, elt);
    }
  }
  
  return NGX_CONF_OK;
}

static void init_proxy_handler(ngx_stream_request_t* r);
static void proxy_handle_request(ngx_stream_request_t*);

char *http_proxy_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_request_core_srv_conf_t* cscf;
  ngx_url_t                    u;
  ngx_str_t                   *value, *url;
  
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  if (cscf->upstream) {
    return "is duplicate";
  }
  
  value = cf->args->elts;
  
  url = &value[1];
  
  ngx_memzero(&u, sizeof(ngx_url_t));
  
  u.url = *url;
  u.no_resolve = 1;
  
  cscf->upstream = ngx_stream_upstream_add(cf, &u, 0);
  if (cscf->upstream == NULL) {
    return NGX_CONF_ERROR;
  }
  
  cscf->init_proxy_handler = init_proxy_handler;
  cscf->proxy_handle_request = proxy_handle_request;
  
  return NGX_CONF_OK;
}

#pragma mark - handler

static void peer_write_handler(ngx_event_t* e);
static void peer_read_handler(ngx_event_t* e);
static void peer_dummy_handler(ngx_event_t* e){}
static void peer_read_line_handler(ngx_event_t* e);
static void peer_read_header_handler(ngx_event_t* e);
static void peer_read_close_end_handler(ngx_event_t* e);
static void peer_read_content_len_handler(ngx_event_t* e);
static void peer_read_chunked_handler(ngx_event_t* e);
static ngx_int_t process_chunk_size(ngx_stream_request_t* r);
static ngx_int_t process_chunk_data(ngx_stream_request_t* r);

static void init_proxy_handler(ngx_stream_request_t* r) {
  ngx_connection_t* pc = r->upstream->peer.connection;
  ngx_connection_t* c = r->session->connection;
  
  pc->read->handler = peer_read_handler;
  if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upstream ngx_handle_read_event error");
    return;
  }
  pc->write->handler = peer_write_handler;
  
  c->log->action = "proxy handle request";
}

static ngx_str_t get_a_header_value(ngx_str_t name, ngx_str_t value
                                    , ngx_stream_request_t* r) {
  ngx_stream_session_t* s = r->session;
  
  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  if (value.len != 0) {
    if (value.data[0] != '$') {
      return value;
    }
    value.data += 1;
    value.len -= 1;
    ngx_str_t r_value = ngx_stream_request_get_header(r, value);
    if (r_value.len != 0) {
      return r_value;
    }
    value = ngx_stream_get_variable_value(s, value);
    if (value.len != 0) {
      return value;
    }
  }
  
  ngx_str_t* p = ngx_list_hash_find(pscf->header_if_empty_table, name);
  if (p != NULL) {
    return *p;
  }
  
  ngx_str_null(&value);
  return value;
}

#define safely_set_buffer(r, buffer, src, n) \
  do{ \
    if (buffer->last + n > buffer->end) { \
      ngx_stream_request_failed(r, "http head buffer is too small"); \
      return; \
    } \
    ngx_memcpy(buffer->last, src, n); \
    head->last += n; \
  } while(0)

static void proxy_handle_request(ngx_stream_request_t* r) {
  ngx_connection_t* pc = r->upstream->peer.connection;
  ngx_stream_session_t* s = r->session;
  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  
  // 预分配这么长，头部如果超过这么多，将返回错误
  ngx_buf_t* head = ngx_create_temp_buf(r->pool, 2048);
  ngx_str_t tmp_str = ngx_string("POST ");
  if (ngx_chain_len(r->data) == 0) {
    ngx_str_set(&tmp_str, "GET ");
  }
  safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  
  tmp_str = pscf->uri;
  ngx_str_t uri_name = ngx_string("URI");
  tmp_str = get_a_header_value(uri_name, tmp_str, r);
  if (tmp_str.len == 0) {
    ngx_str_set(&tmp_str, "/ ");
  }
  safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  
  ngx_str_set(&tmp_str, " HTTP/1.1\r\n");
  safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  
  ngx_flag_t hasHostHead = 0;
  if (pscf->set_header != NULL && pscf->set_header->nelts != 0) {
    ngx_keyval_t* keyval = pscf->set_header->elts;
    for (ngx_uint_t i = 0; i < pscf->set_header->nelts; ++i) {
      ngx_str_t value = get_a_header_value(keyval[i].key, keyval[i].value, r);
      if (value.len == 0) {
        continue;
      }
      if (keyval[i].key.len == 4 && ngx_memcmp(keyval[i].key.data, "Host", 4) == 0) {
        hasHostHead = 1;
      }
      safely_set_buffer(r, head, keyval[i].key.data, keyval[i].key.len);
      ngx_str_set(&tmp_str, ": ");
      safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
      safely_set_buffer(r, head, value.data, value.len);
      ngx_str_set(&tmp_str, "\r\n");
      safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
    }
  }
  
  if (!hasHostHead) {
    ngx_str_set(&tmp_str, "Host: ");
    safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
    safely_set_buffer(r, head, r->upstream->peer.name->data
                      , r->upstream->peer.name->len);
    ngx_str_set(&tmp_str, "\r\n");
    safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  }
  
  if (ngx_chain_len(r->data) != 0) {
    ngx_str_set(&tmp_str, "Content-Length: ");
    safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
    u_char len[30];
    ngx_memzero(len, 30);
    ngx_sprintf(len, "%ud\r\n", ngx_chain_len(r->data));
    safely_set_buffer(r, head, len, ngx_strlen(len));
  }
  
  ngx_str_set(&tmp_str, "\r\n");
  safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  
  ngx_chain_t* chain = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  chain->buf = head;
  chain->next = r->data;
  r->data = chain;
  
  ngx_add_timer(pc->write, cscf->send_timeout);
  ngx_post_event(pc->write, &ngx_posted_events);
}

static void peer_write_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
//  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  
  if (e->timedout) {
    ngx_stream_request_failed(r, "upsteam send timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  
  /**
   ngx_darwin_sendfile_chain.c 中的ngx_output_chain_to_iovec没有考虑ngx_buf_t size=0
   的情况，会造成writev 卡死的bug
   */
  ngx_regular_request_data(r);
  if (r->data == NULL) {
    e->handler = peer_dummy_handler;
    ngx_add_timer(c->read, cscf->response_timeout);
    return;
  }
  ngx_chain_t* rc = c->send_chain(c, r->data, 0);
  if (rc == NGX_CHAIN_ERROR) {
    ngx_stream_request_failed(r, "upsteam send error");
    return;
  }
  if (rc == NULL) {
    e->handler = peer_dummy_handler;
    ngx_add_timer(c->read, cscf->response_timeout);
    return;
  }
  
  r->data = rc;
  ngx_add_timer(e, cscf->send_timeout);
  if (ngx_handle_write_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_write_event error");
    return;
  }
}

static void peer_read_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  
  if (e->timedout) {
    ngx_stream_request_failed(r, "upsteam response timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(http_proxy_ctx_t));
    ngx_stream_request_set_ctx(r, ctx, this_module);
  }
  ctx->receive_buffer = ngx_create_temp_buf(r->pool, 1000);
  ctx->last_is_crlf = 0;
  ctx->response_header = ngx_pcalloc(r->pool, sizeof(ngx_list_hash_t));
  ngx_list_hash_init(ctx->response_header, 11, r->pool);
  
  e->handler = peer_read_line_handler;
  e->handler(e);
}

static void peer_read_line_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
//  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  if (e->timedout) {
    ngx_stream_request_failed(r, "upsteam read timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  
  // 因为ctx->receive_buffer 的空间大小远大于 http status line的长度
  // 所以 不存在receive_buffer的空间问题造成找不到http status line 的结束标志
  // 因此  不用循环 read-do
  ssize_t n = c->recv(c, ctx->receive_buffer->last
                      , ctx->receive_buffer->end-ctx->receive_buffer->last);
  if (n <= 0 && n != NGX_AGAIN) {
    ngx_stream_request_failed(r, "upsteam peer_read_line_handler failed");
    return;
  }
  
  do {
    if (n == NGX_AGAIN) {
      break;
    }
    ctx->receive_buffer->last += n;
    u_char* p = ctx->receive_buffer->pos;
    ngx_flag_t line = 0;
    for (; p+1 < ctx->receive_buffer->last; ++p) {
      if (*p == CR && *(p+1) == LF) {
        line = 1;
        break;
      }
    }
    if (line == 0) {
      break;
    }
    ctx->receive_buffer->pos += 8; // skip HTTP/1.1
    while (*ctx->receive_buffer->pos == ' ') {
      ctx->receive_buffer->pos++;
    }
    *p = '\0';
    if (ngx_memcmp(ctx->receive_buffer->pos, "200", 3) != 0) {
      ngx_stream_request_failed(r, (char*)ctx->receive_buffer->pos);
      return;
    }
    ctx->receive_buffer->pos = p+2;
    ngx_regular_buf(ctx->receive_buffer);
    e->handler = peer_read_header_handler;
    ngx_add_timer(e, cscf->receive_timeout);
    e->handler(e);
    return;
  } while (0);
  
  ngx_add_timer(e, cscf->receive_timeout);
  if (ngx_handle_read_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
    return;
  }
}

static ngx_int_t parse_http_res_header(ngx_stream_request_t* r) {
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  ngx_buf_t* buf = ctx->receive_buffer;
  ngx_int_t end_head = 0;
  for (u_char* p = buf->pos; p+1 < buf->last; ++p) {
    if (!(*p == CR && *(p+1) == LF)) {
      ctx->last_is_crlf = 0;
      continue;
    }
    if (ctx->last_is_crlf == 1) {
      buf->pos = p+2;
      end_head = 1;
      break;
    }
    
    ctx->last_is_crlf = 1;
    u_char* p1 = buf->pos;
    u_char* p2 = ngx_strlchr(buf->pos, p, ':');
    if (p2 == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->session->connection->log, 0, "http header error");
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
    
    // p1~p2  key; p3~p  value
    ngx_str_t key;
    key.len = p2-p1;
    key.data = ngx_pcalloc(r->pool, key.len);
    ngx_memcpy(key.data, p1, key.len);
    ngx_str_t value;
    value.len = p-p3;
    value.data = ngx_pcalloc(r->pool, value.len);
    ngx_memcpy(value.data, p3, value.len);
    ngx_list_hash_elt_t* elt = ngx_pcalloc(r->pool, sizeof(ngx_list_hash_elt_t));
    elt->key = key;
    elt->value = value;
    ngx_list_hash_insert(ctx->response_header, elt);
    
    p = buf->pos - 1;
  }
  
  return end_head == 1 ? NGX_OK : NGX_AGAIN;
}

static void set_session(ngx_stream_request_t* r, ngx_array_t* keyvals
                        , ngx_uint_t force_rewrite) {
  ngx_stream_session_t* s = r->session;
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  if (keyvals == NULL || keyvals->nelts == 0) {
    return;
  }
  ngx_keyval_t* elts = keyvals->elts;
  ngx_uint_t len = keyvals->nelts;
  for (ngx_uint_t i = 0; i < len; ++i) {
    ngx_str_t key = elts[i].key;
    ngx_str_t value = elts[i].value;
    if (value.data[0] == '$') {
      value.data++;
      value.len--;
      ngx_str_t* v = ngx_list_hash_find(ctx->response_header, value);
      if (v == NULL) {
        continue;
      }
      value = *v;
    }
    ngx_stream_set_variable_value(s, key, value, force_rewrite);
  }
}

static void peer_read_header_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  if (e->timedout) {
    ngx_stream_request_failed(r, "upsteam read timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  
  do {
    ngx_int_t rc = parse_http_res_header(r);
    ngx_regular_buf(ctx->receive_buffer);
    if (rc == NGX_ERROR) {
      ngx_stream_request_failed(r, "http response header error");
      return;
    }
    if (rc == NGX_OK) {
      break;
    }
    ssize_t n = c->recv(c, ctx->receive_buffer->last
                        , ctx->receive_buffer->end - ctx->receive_buffer->last);
    if (n <= 0 && n != NGX_AGAIN) {
      ngx_stream_request_failed(r, "upsteam peer_read_line_handler failed");
      return;
    }
    if (n == NGX_AGAIN) {
      ngx_add_timer(e, cscf->receive_timeout);
      if (ngx_handle_read_event(e, 0) != NGX_OK) {
        ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
        return;
      }
      return;
    }
    ctx->receive_buffer->last += n;
  } while (1);
  
  // read data
  set_session(r, pscf->set_session, 1);
  set_session(r, pscf->set_session_if_empty, 0);
  
  // ctx->receive_buffer 可能遗留有数据，在下面的逻辑中需要处理
  
  ngx_str_t key = ngx_string("Content-Length");
  ngx_str_t *content_len;
  if ((content_len = ngx_list_hash_find(ctx->response_header, key)) != NULL) {
    ngx_int_t len = ngx_atoi(content_len->data, content_len->len);
    e->handler = peer_read_content_len_handler;
    e->handler(e);
    r->data->buf = ctx->receive_buffer;
    ngx_int_t left_len = len-ngx_buf_size(ctx->receive_buffer);
    if (left_len == 0) {
      r->data->next = NULL;
    } else {
      r->data->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      r->data->next->buf = ngx_create_temp_buf(r->pool, left_len);
      r->data->next->next = NULL;
    }
    return;
  }
  
  ngx_str_set(&key, "Transfer-Encoding");
  if ((content_len = ngx_list_hash_find(ctx->response_header, key)) != NULL) {
    if (content_len->len != 7 || ngx_memcmp(content_len->data, "chunked", 7) != 0) {
      u_char reson[50];
      ngx_memzero(reson, 50);
      ngx_sprintf(reson
      , "http response header Transfer-Encoding isnt chunked, which is %V", content_len);
      ngx_stream_request_failed(r, (char*)reson);
      return;
    }
    r->data->buf = ctx->receive_buffer;
    r->data->next = NULL;
    ctx->chunk_data_handler = process_chunk_size;
    e->handler = peer_read_chunked_handler;
    e->handler(e);
    return;
  }
  
  r->data->buf = ctx->receive_buffer;
  r->data->next = NULL;
  e->handler = peer_read_close_end_handler;
  e->handler(e);
}

static void peer_read_close_end_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
//  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  
  if (e->timedout) {
    ngx_stream_request_failed(r, "upsteam read timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  ngx_chain_t* last = r->data;
  for (; last->next != NULL; last = last->next) {}
  if (last->buf->end-last->buf->last == 0) {
    last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    last->buf = ngx_create_temp_buf(r->pool, 1024);
    last = last->next;
  }
  ssize_t n = c->recv(c, last->buf->last, last->buf->end-last->buf->last);
  if (n <= 0 && n != NGX_AGAIN && e->eof != 1) {
    ngx_stream_request_failed(r, "upsteam read error");
    return;
  }
  if (e->eof) {
    handle_request_done(r);
    return;
  }
  do {
    if (n == NGX_AGAIN) {
      break;
    }
    last->buf->last += n;
    if (last->buf->last == last->buf->end) {
      e->handler(e); // 递归执行
      return;
    }
  } while (0);
  
  ngx_add_timer(e, cscf->receive_timeout);
  if (ngx_handle_read_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
    return;
  }
}

static void peer_read_content_len_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
//  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  
  if (e->timedout) {
    ngx_stream_request_failed(r, "upsteam read timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  ngx_chain_t* last = r->data;
  while (last->next != NULL) {
    last = last->next;
  }
  ssize_t n = c->recv(c, last->buf->last, last->buf->end - last->buf->last);
  if (n <= 0 && n != NGX_AGAIN) {
    ngx_stream_request_failed(r, "upsteam read error");
    return;
  }
  do {
    if (n == NGX_AGAIN) {
      break;
    }
    r->data->buf->last += n;
    if (r->data->buf->last == r->data->buf->end) {
      handle_request_done(r);
      return;
    }
  } while (0);
  
  ngx_add_timer(e, cscf->receive_timeout);
  if (ngx_handle_read_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
    return;
  }
}

static u_char get_asscii_value(u_char asscii) {
  if (asscii >= '0' && asscii <= '9') {
    return asscii - '0';
  }
  if (asscii >= 'a' && asscii <= 'f') {
    return asscii-'a' + 10;
  }
  if (asscii >= 'A' && asscii <= 'F') {
    return asscii-'A' + 10;
  }
  return 0;
}

/* Macros for min/max. */
#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif /* MIN */
#ifndef MAX
#define	MAX(a,b) (((a)>(b))?(a):(b))
#endif	/* MAX */

static ngx_int_t process_chunk_size(ngx_stream_request_t* r) {
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  ngx_chain_t* last = r->data;
  while (last->next != NULL) {
    last = last->next;
  }
  ngx_buf_t* buffer = last->buf;
  for (u_char* p = buffer->pos; p+1 < buffer->last; ++p) {
    if (!(*p == CR && *(p+1) == LF)) {
      continue;
    }
    *p = '\0';
    int len = 0;
    for (u_char* p1 = buffer->pos; p1 < p; ++p1) {
      len = len*16 + get_asscii_value(*p1);
    }
    if (len == 0) {
      ctx->chunk_is_end = 1;
    }
    buffer->pos = p+2;
    len += 2; // 2: CRLF after data
    ctx->chunk_data_handler = process_chunk_data;
    if (len <= ngx_buf_size(buffer)) {
      if (ctx->chunk_is_end == 1) {
        last->buf->last = last->buf->pos + len - 2; // remove CRLF
        return NGX_OK;
      }
      last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      last->next->buf = ngx_create_temp_buf(r->pool
                                            , MAX(ngx_buf_size(buffer)-len, 500));
      ngx_memcpy(last->next->buf->last, buffer->pos+len, ngx_buf_size(buffer)-len);
      last->next->buf->last += ngx_buf_size(buffer)-len;
      last->buf->last = last->buf->pos + len - 2; // remove CRLF
      ctx->chunk_data_handler = process_chunk_size; // continue process size
    } else if (len == ngx_buf_size(buffer) + 1){
      buffer->last -= 1; // remove CR
      last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      last->next->buf = ngx_create_temp_buf(r->pool, 1); // receive LF
    } else {
      last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      last->next->buf = ngx_create_temp_buf(r->pool, len-ngx_buf_size(buffer));
    }
    return NGX_DONE;
  }
  if (buffer->last == buffer->end) {
    last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    last->next->buf = ngx_create_temp_buf(r->pool, 500);
  }
  return NGX_AGAIN;
}

static ngx_int_t process_chunk_data(ngx_stream_request_t* r) {
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  ngx_chain_t* last = r->data;
  while (last->next != NULL) {
    last = last->next;
  }
  ngx_buf_t* buffer = last->buf;
  if (buffer->last != buffer->end) {
    return NGX_AGAIN;
  }
  
  if (ngx_buf_size(buffer) == 1) {
    buffer->last = buffer->pos; // remove LF
  } else {
    buffer->last -= 2; // remove CRLF
  }
  if (ctx->chunk_is_end == 1) {
    return NGX_OK;
  }
  
  last->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  last->next->buf = ngx_create_temp_buf(r->pool, 500);
  ctx->chunk_data_handler = process_chunk_size;
  
  return NGX_DONE;
}

static void peer_read_chunked_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
//  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  if (e->timedout) {
    ngx_stream_request_failed(r, "upstream read timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  
  do {
    ngx_int_t rc = NGX_OK;
    do {
      rc = ctx->chunk_data_handler(r);
    } while (rc == NGX_DONE);
    if (rc == NGX_OK) {
      handle_request_done(r);
      return;
    }
    ngx_chain_t* last = r->data;
    while (last->next != NULL) {
      last = last->next;
    }
    ssize_t n = c->recv(c, last->buf->last, last->buf->end - last->buf->last);
    if (n <= 0 && n != NGX_AGAIN) {
      ngx_stream_request_failed(r, "upstream read error");
      return;
    }
    if (n == NGX_AGAIN) {
      break;
    }
    last->buf->last += n;
  } while (1);
  
  ngx_add_timer(e, cscf->receive_timeout);
  if (ngx_handle_read_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
    return;
  }
}

