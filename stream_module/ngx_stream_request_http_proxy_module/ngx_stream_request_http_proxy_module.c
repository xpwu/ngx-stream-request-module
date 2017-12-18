//
//  ngx_stream_request_http_proxy_module.c
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/9.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_http_proxy_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - list hash
#endif

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

ngx_list_hash_elt_t* ngx_list_hash_find(ngx_list_hash_t* hashtable, ngx_str_t key) {
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
      return elt;
    }
  }
  return NULL;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - conf
#endif

static void *ngx_stream_http_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_http_proxy_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child);
static ngx_int_t preconfiguration(ngx_conf_t *cf);

char *http_proxy_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct{
  ngx_str_t key;
  ngx_stream_complex_value_t value;
} http_proxy_header_t;

typedef struct {
  ngx_array_t* headers_temp; // <ngx_keyval_t>
  ngx_array_t headers; // [http_proxy_header_t]
  ngx_int_t header_hash_size;
  ngx_url_t url;
  ngx_stream_complex_value_t uri;
  
}http_proxy_srv_conf_t;

typedef struct{
  ngx_buf_t* receive_buffer;
  ngx_int_t last_is_crlf;
  
  ngx_int_t (*chunk_data_handler)(ngx_stream_request_t* r);
  ngx_flag_t chunk_is_end;
  
  ngx_int_t content_length;
  ngx_int_t chunked;
} http_proxy_ctx_t;

typedef struct{
  ngx_list_hash_t* response_header;
} http_proxy_session_ctx_t;

static ngx_int_t
http_proxy_resp_header_get_value(ngx_stream_session_t *s,
                               ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t empty_value(ngx_stream_session_t *s,
                             ngx_stream_variable_value_t *v, uintptr_t data){
  v->data = (u_char*)"";
  v->valid = 0;
  v->not_found = 1;
  v->len = 0;
  v->no_cacheable = 0;
  
  return NGX_OK;
}

static ngx_stream_variable_t  ngx_stream_core_variables[] = {
  { ngx_string("http_proxy_Content-Lenght"), NULL
    , empty_value,
    0, 0, 0 },
  { ngx_string("http_proxy_Transfer-Encoding"), NULL, empty_value,
    0, 0, 0 },
  { ngx_string("http_proxy_"), NULL, http_proxy_resp_header_get_value,
    0, NGX_STREAM_VAR_PREFIX, 0 },
  
  { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_command_t  ngx_stream_http_proxy_commands[] = {
  
  { ngx_string("http_proxy_pass"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    http_proxy_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("http_proxy_resp_headers_hash_size"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(http_proxy_srv_conf_t, header_hash_size),
    NULL},
  { ngx_string("http_proxy_add_header"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_keyval_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(http_proxy_srv_conf_t, headers_temp),
    NULL},
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_http_proxy_module_ctx = {
  preconfiguration,
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

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - conf impl
#endif

static ngx_int_t preconfiguration(ngx_conf_t *cf) {
  ngx_stream_variable_t  *var, *v;
  
  for (v = ngx_stream_core_variables; v->name.len; v++) {
    var = ngx_stream_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      return NGX_ERROR;
    }
    
    var->get_handler = v->get_handler;
    var->data = v->data;
  }
  
  return NGX_OK;
}

static void *ngx_stream_http_proxy_create_srv_conf(ngx_conf_t *cf) {
  http_proxy_srv_conf_t  *pscf;
  
  pscf = ngx_pcalloc(cf->pool, sizeof(http_proxy_srv_conf_t));
  if (pscf == NULL) {
    return NULL;
  }
  pscf->header_hash_size = NGX_CONF_UNSET;
  
  return pscf;
}

static char *ngx_stream_http_proxy_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child) {
  http_proxy_srv_conf_t *prev = parent;
  http_proxy_srv_conf_t *conf = child;
  ngx_keyval_t  *con;
  ngx_int_t i;
  ngx_str_t conkey;
  ngx_str_t host = ngx_string("Host"),hostdefault=ngx_string("127.0.0.1");
  http_proxy_header_t *header_value;
  ngx_stream_request_compile_complex_value_t   ccv;

  if (conf->url.url.len == 0) {
    conf->url = prev->url;
  }
  
  if (conf->uri.value.len == 0) {
    conf->uri = prev->uri;
  }
  
  ngx_conf_merge_value(conf->header_hash_size, prev->header_hash_size, 11);
  
  //merge header
  conf->headers_temp = ngx_merge_key_val_array(cf->pool, prev->headers_temp
                                               , conf->headers_temp);
  // find host
  con = conf->headers_temp->elts;
  for (i = 0; i < conf->headers_temp->nelts; ++i) {
    conkey = con[i].key;
    if (host.len == conkey.len
        && (ngx_strncmp(host.data, conkey.data, host.len) == 0)) {
      break;
    }
  }
  if (i >= conf->headers_temp->nelts) {
    con = ngx_array_push(conf->headers_temp);
    con->key = host;
    con->value = hostdefault;
    if (conf->url.url.len != 0 && conf->url.host.len != 0) {
      con->value = conf->url.host;
    }
  }
  
  // compile
  ngx_array_init(&conf->headers, cf->pool
                 , conf->headers_temp->nelts, sizeof(http_proxy_header_t));
  con = conf->headers_temp->elts;
  for (i = 0; i < conf->headers_temp->nelts; ++i) {
    header_value = ngx_array_push(&conf->headers);
    header_value->key = con[i].key;
    
    ngx_memzero(&ccv, sizeof(ngx_stream_request_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &con[i].value;
    ccv.complex_value = &header_value->value;
    
    if (ngx_stream_request_compile_complex_value(&ccv) != NGX_OK) {
      return NGX_CONF_ERROR;
    }
  }
  
  return NGX_CONF_OK;
}

static ngx_int_t proxy_handle_request(ngx_stream_request_t*);

char *http_proxy_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  http_proxy_srv_conf_t* pscf = conf;
  ngx_stream_request_core_srv_conf_t* cscf;
  ngx_str_t                   *value;
  ngx_stream_request_handler_t* handler;
  ngx_stream_request_compile_complex_value_t   ccv;
  ngx_str_t     uri = ngx_string("/");
  
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  if (cscf->upstream) {
    return "is duplicate";
  }
  
  value = cf->args->elts;
  
  pscf->url.url = value[1];
  pscf->url.no_resolve = 1;
  
  cscf->upstream = ngx_stream_upstream_add(cf, &pscf->url, 0);
  if (cscf->upstream == NULL) {
    return NGX_CONF_ERROR;
  }
  
  // ngx_parse_url have called by ngx_stream_upstream_add
  if (pscf->url.uri.len != 0) {
    uri = pscf->url.uri;
  }
  ngx_memzero(&ccv, sizeof(ngx_stream_request_compile_complex_value_t));
  ccv.cf = cf;
  ccv.value = &uri;
  ccv.complex_value = &pscf->uri;
  
  if (ngx_stream_request_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
  }
  
  handler = ngx_stream_request_add_handler(cscf);
  handler->handle_request = proxy_handle_request;
  
  return NGX_CONF_OK;
}

static ngx_int_t
http_proxy_resp_header_get_value(ngx_stream_session_t *s,
                                 ngx_stream_variable_value_t *v, uintptr_t data) {
  http_proxy_session_ctx_t* s_ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_str_t* key = (ngx_str_t*)data;
  ngx_str_t prefix = ngx_string("http_proxy_");
  
  key->len -= prefix.len;
  key->data += prefix.len;
  
  ngx_list_hash_elt_t* elt = ngx_list_hash_find(s_ctx->response_header, *key);
  if (elt == NULL) {
    v->len = 0;
    v->valid = 0;
    v->no_cacheable = 1;
    v->not_found = 1;
    v->data = NULL;
  } else {
    v->len = (unsigned)elt->value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = elt->value.data;
  }
  
  return NGX_OK;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - handler
#endif

static void proxy_handle_request_inte(ngx_stream_request_t* r);
static void upstream_connected(ngx_stream_request_t*);
static void upstream_connect_failed(ngx_stream_request_t*, char* reason);
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

static ngx_int_t proxy_handle_request(ngx_stream_request_t* r) {
  r->upstream->upstream_connected = upstream_connected;
  r->upstream->upstream_connect_failed = upstream_connect_failed;
  ngx_stream_request_upstream_connect(r);
  
  r->handler_index++;
  return NGX_AGAIN;
}

static void upstream_connected(ngx_stream_request_t* r) {
  ngx_connection_t* pc = r->upstream->upstream.peer.connection;

  pc->read->handler = peer_read_handler;
  if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
    ngx_stream_request_error(r, "nginx error: upstream ngx_handle_read_event error");
    ngx_stream_handle_request(r);
    return;
  }
  pc->write->handler = peer_write_handler;
  
  proxy_handle_request_inte(r);
}

static void upstream_connect_failed(ngx_stream_request_t* r, char* reason) {
  ngx_stream_request_error(r, "nginx error: upstream ngx_handle_read_event error");
  ngx_stream_handle_request(r);
}

#define safely_set_buffer(r, buffer, src, n) \
  do{ \
    if (buffer->last + n > buffer->end) { \
      ngx_stream_request_error(r, "nginx error: http proxy head buffer is too small"); \
      ngx_stream_handle_request(r); \
      return; \
    } \
    ngx_memcpy(buffer->last, src, n); \
    head->last += n; \
  } while(0)

#define complex_value(r, complex, text) \
  do { \
    if (ngx_stream_request_complex_value(r, complex, text) != NGX_OK) { \
      u_char p[100]; \
      ngx_memzero(p, sizeof(p)); \
      ngx_sprintf(p, "nginx error: http proxy complex_value error: %V" \
              , &pscf->uri.value); \
      ngx_stream_request_error(r, (char*)p); \
      ngx_stream_handle_request(r); \
      return; \
    } \
  } while(0)

#define ngx_stream_request_failed(r, error) \
  do {   \
    ngx_stream_request_error(r, error); \
    ngx_stream_handle_request(r); \
  }while(0)

static void proxy_handle_request_inte(ngx_stream_request_t* r) {
  ngx_connection_t* pc = r->upstream->upstream.peer.connection;
  ngx_stream_session_t* s = r->session;
  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_core_srv_conf_t* cscf;
  ngx_uint_t i = 0;
  http_proxy_header_t *headers;
  
  cscf = ngx_stream_get_module_srv_conf(s, core_module);
  
  // 预分配这么长，头部如果超过这么多，将返回错误
  ngx_buf_t* head = ngx_create_temp_buf(r->pool, 2048);
  ngx_str_t tmp_str = ngx_string("POST ");
  if (ngx_chain_len(r->data) == 0) {
    ngx_str_set(&tmp_str, "GET ");
  }
  safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  
  complex_value(r, &pscf->uri, &tmp_str);
  safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  
  ngx_str_set(&tmp_str, " HTTP/1.1\r\n");
  safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
  
  headers = pscf->headers.elts;
  for (i = 0; i < pscf->headers.nelts; ++i) {
    ngx_str_t tmp2_str;
    complex_value(r, &headers[i].value, &tmp2_str);
    if (tmp2_str.len == 0 || tmp_str.data == NULL) {
      continue;
    }
    safely_set_buffer(r, head, headers[i].key.data, headers[i].key.len);
    ngx_str_set(&tmp_str, ": ");
    safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
    tmp_str = tmp2_str;
    safely_set_buffer(r, head, tmp_str.data, tmp_str.len);
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
  
  ngx_add_timer(pc->write, cscf->send_to_proxy_timeout);
  ngx_post_event(pc->write, &ngx_posted_events);
}

static void peer_write_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
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
  ngx_stream_request_regular_data(r);
  if (r->data == NULL) {
    e->handler = peer_dummy_handler;
    ngx_add_timer(c->read, cscf->proxy_response_timeout);
    return;
  }
  ngx_chain_t* rc = c->send_chain(c, r->data, 0);
  if (rc == NGX_CHAIN_ERROR) {
    ngx_stream_request_failed(r, "upsteam send error");
    return;
  }
  if (rc == NULL) {
    e->handler = peer_dummy_handler;
    ngx_add_timer(c->read, cscf->proxy_response_timeout);
    return;
  }
  
  r->data = rc;
  ngx_add_timer(e, cscf->send_to_proxy_timeout);
  if (ngx_handle_write_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_write_event error");
    return;
  }
}

static void peer_read_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
  http_proxy_srv_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
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
    ctx->content_length = -1;
    ctx->chunked = 0;
    ngx_stream_request_set_ctx(r, ctx, this_module);
  }
  ctx->receive_buffer = ngx_create_temp_buf(r->pool, 1000);
  ctx->last_is_crlf = 0;
  
  http_proxy_session_ctx_t* s_ctx = ngx_stream_get_module_ctx(s, this_module);
  if (s_ctx == NULL) {
    s_ctx = ngx_pcalloc(s->connection->pool, sizeof(http_proxy_session_ctx_t));
    ngx_stream_set_ctx(s, s_ctx, this_module);
    s_ctx->response_header = ngx_pcalloc(s->connection->pool
                                         , sizeof(ngx_list_hash_t));
    ngx_list_hash_init(s_ctx->response_header, pscf->header_hash_size, r->pool);
  }
  
  e->handler = peer_read_line_handler;
  e->handler(e);
}

static void peer_read_line_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
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
    ngx_add_timer(e, cscf->receive_from_proxy_timeout);
    e->handler(e);
    return;
  } while (0);
  
  ngx_add_timer(e, cscf->receive_from_proxy_timeout);
  if (ngx_handle_read_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
    return;
  }
}

static ngx_int_t parse_http_res_header(ngx_stream_request_t* r) {
  http_proxy_ctx_t* ctx = ngx_stream_request_get_module_ctx(r, this_module);
  ngx_buf_t* buf = ctx->receive_buffer;
  ngx_int_t end_head = 0;
  u_char* p = NULL;
  ngx_stream_session_t *s = r->session;
  http_proxy_session_ctx_t* s_ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_pool_t* s_pool = s->connection->pool;
  
	for (p = buf->pos; p+1 < buf->last; ++p) {
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
    
    // parse header
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
    key.data = p1;
    ngx_str_t value;
    value.len = p-p3;
    value.data = p3;
    
    p = buf->pos - 1;
    
    //----
    ngx_str_t key1 = ngx_string("Content-Length");
    if (key.len == key1.len
        &&(ngx_memcmp(key.data, key1.data, key1.len))) {
      ctx->content_length = ngx_atoi(value.data, value.len);
    }
    ngx_str_set(&key1, "Transfer-Encoding");
    if (key.len == key1.len
        &&(ngx_memcmp(key.data, key1.data, key1.len))) {
      ngx_str_set(&key1, "chunked");
      if (value.len == key1.len
          &&(ngx_memcmp(value.data, key1.data, key1.len))) {
        ctx->chunked = 1;
      } else {
        u_char reason[100];
        ngx_memzero(reason, 100);
        ngx_sprintf(reason
                    , "http response header Transfer-Encoding isnt chunked, which is %V"
                    , &value);
        ngx_stream_request_failed(r, (char*)reason);
        return NGX_ERROR;
      }
    }
    
    // hash
    u_char lowkey[50];
    ngx_strlow(lowkey, key.data, key.len);
    key.data = lowkey;
    ngx_list_hash_elt_t *elt;
    do {
      if ((elt = ngx_list_hash_find(s_ctx->response_header, key)) != NULL) {
        if (elt->value.len == value.len
            && (ngx_memcmp(elt->value.data, value.data, value.len) == 0)) {
          break;
        }
        if (elt->value.len >= value.len) {
          ngx_memcpy(elt->value.data, value.data, value.len);
          elt->value.len = value.len;
          break;
        }
        // TODO: 后端重复的返回同一key的不同值时, 会造成内存泄露
        ngx_pfree(s_pool, elt->value.data); // 只会删除大的内存
        elt->value.data = ngx_pcalloc(s_pool, value.len);
        ngx_memcpy(elt->value.data, value.data, value.len);
        elt->value.len = value.len;
    
        break;
      }
      
      elt = ngx_pcalloc(s_pool, sizeof(ngx_list_hash_elt_t));
      elt->key.len = key.len;
      elt->key.data = ngx_pcalloc(s_pool, key.len);
      ngx_memcpy(elt->key.data, key.data, key.len);
      elt->value.len = value.len;
      elt->value.data = ngx_pcalloc(s_pool, value.len);
      ngx_memcpy(elt->value.data, value.data, value.len);
      ngx_list_hash_insert(s_ctx->response_header, elt);
    } while (0);
  }
  
  return end_head == 1 ? NGX_OK : NGX_AGAIN;
}

static void peer_read_header_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
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
      ngx_add_timer(e, cscf->receive_from_proxy_timeout);
      if (ngx_handle_read_event(e, 0) != NGX_OK) {
        ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
        return;
      }
      return;
    }
    ctx->receive_buffer->last += n;
  } while (1);
  
  // ctx->receive_buffer 可能遗留有数据，在下面的逻辑中需要处理
  if (ctx->content_length != -1) {
    e->handler = peer_read_content_len_handler;
    e->handler(e);
    r->data->buf = ctx->receive_buffer;
    ngx_int_t left_len = ctx->content_length-ngx_buf_size(ctx->receive_buffer);
    if (left_len == 0) {
      r->data->next = NULL;
    } else {
      r->data->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      r->data->next->buf = ngx_create_temp_buf(r->pool, left_len);
      r->data->next->next = NULL;
    }
    return;
  }
  
  if (ctx->chunked == 1) {
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
    ngx_stream_handle_request(r);
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
  
  ngx_add_timer(e, cscf->receive_from_proxy_timeout);
  if (ngx_handle_read_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
    return;
  }
}

static void peer_read_content_len_handler(ngx_event_t* e) {
  ngx_connection_t* c = e->data;
  ngx_stream_request_t* r = c->data;
  ngx_stream_session_t* s = r->session;
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
      ngx_stream_handle_request(r);
      return;
    }
  } while (0);
  
  ngx_add_timer(e, cscf->receive_from_proxy_timeout);
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
  u_char* p = NULL;
	for (p = buffer->pos; p+1 < buffer->last; ++p) {
    if (!(*p == CR && *(p+1) == LF)) {
      continue;
    }
    *p = '\0';
    int len = 0;
    u_char* p1 = NULL;
		for (p1 = buffer->pos; p1 < p; ++p1) {
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
      ngx_stream_handle_request(r);
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
  
  ngx_add_timer(e, cscf->receive_from_proxy_timeout);
  if (ngx_handle_read_event(e, 0) != NGX_OK) {
    ngx_stream_request_failed(r, "upsteam ngx_handle_read_event error");
    return;
  }
}

