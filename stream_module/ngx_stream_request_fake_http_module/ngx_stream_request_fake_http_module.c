//
//  ngx_stream_request_content_logic.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/11/17.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_fake_http_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

/*
 * content protocol:
 *    request ---
 *      reqid | headers | header-end-flag | data
 *        reqid: 4 bytes, net order;
 *        headers: < key-len | key | value-len | value > ... ;  [optional]
 *          key-len: 1 byte,  key-len = sizeof(key);
 *          value-len: 1 byte, value-len = sizeof(value);
 *        header-end-flag: 1 byte, === 0;                       [optional]
 *        data:       [optional]
 *
 *    response ---
 *      reqid | status | data
 *        reqid: 4 bytes, net order;
 *        status: 1 byte, 0---success, 1---failed
 *        data: if status==success, data=<app data>    [optional]
 *              if status==failed, data=<error reason>
 *
 *
 *    reqid = 1: server push to client
 *
 */

static ngx_int_t preconfiguration(ngx_conf_t *cf);
char *fake_http_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *fake_http_log_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_stream_fake_http_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_fake_http_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child);

typedef struct{
  ngx_uint_t handle_index;
  ngx_stream_request_complex_value_t logf;
} fake_http_srv_conf_t;

static ngx_command_t  ngx_stream_fake_http_commands[] = {
  { ngx_string("fake_http_subprotocol"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    fake_http_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("fake_http_log_format"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    fake_http_log_format,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  ngx_null_command
};

static ngx_stream_module_t  ngx_stream_fake_http_module_ctx = {
  preconfiguration,
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  ngx_stream_fake_http_create_srv_conf,   /* create server configuration */
  ngx_stream_fake_http_merge_srv_conf     /* merge server configuration */
};

ngx_module_t  ngx_stream_request_fake_http_module = {
  NGX_MODULE_V1,
  &ngx_stream_fake_http_module_ctx,           /* module context */
  ngx_stream_fake_http_commands,              /* module directives */
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

typedef struct{
  ngx_uint_t  reqid;
  ngx_str_str_rbtree  headers;
} request_ctx;

static ngx_int_t
fhttp_header_get_value(ngx_stream_request_t *r,
                       ngx_stream_request_variable_value_t *v, uintptr_t data);
static ngx_int_t
fhttp_header_get_reqid(ngx_stream_request_t *r,
                       ngx_stream_request_variable_value_t *v, uintptr_t data);

static ngx_stream_request_variable_t  ngx_stream_fhttp_variables[] = {
  { ngx_string("fhttp_reqid"), NULL, fhttp_header_get_reqid,
    0, 0, 0 },
  { ngx_string("fhttp_"), NULL, fhttp_header_get_value,
    0, NGX_STREAM_VAR_PREFIX, 0 },
  
  { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t preconfiguration(ngx_conf_t *cf) {
  ngx_stream_request_variable_t  *var, *v;
  
  for (v = ngx_stream_fhttp_variables; v->name.len; v++) {
    var = ngx_stream_request_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      return NGX_ERROR;
    }
    
    var->get_handler = v->get_handler;
    var->data = v->data;
  }
  
  return NGX_OK;
}

static void *ngx_stream_fake_http_create_srv_conf(ngx_conf_t *cf) {
  fake_http_srv_conf_t  *fscf;
  
  fscf = ngx_pcalloc(cf->pool, sizeof(fake_http_srv_conf_t));
  if (fscf == NULL) {
    return NULL;
  }
  
  fscf->handle_index = NGX_CONF_UNSET_UINT;
  
  return fscf;
}

static char *ngx_stream_fake_http_merge_srv_conf(ngx_conf_t *cf
                                                 , void *parent, void *child) {
  fake_http_srv_conf_t *prev = parent;
  fake_http_srv_conf_t *conf = child;
  
  ngx_conf_merge_uint_value(conf->handle_index
                            , prev->handle_index, NGX_CONF_UNSET_UINT);
  
  if (prev->handle_index == NGX_CONF_UNSET_UINT) {
    ngx_log_error(NGX_LOG_ERR, cf->log
                  , 0, "fake_http handle_index is NGX_CONF_UNSET_UINT");
    NGX_CONF_ERROR;
  }
  
  return NGX_CONF_OK;
}

static ngx_int_t handle_request(ngx_stream_request_t*);
static ngx_int_t build_response(ngx_stream_request_t*);

char *fake_http_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_request_handler_t* handler;
  fake_http_srv_conf_t *fscf = conf;
  
  handler = ngx_stream_request_add_handler(cf);
  fscf->handle_index = handler->index;
  handler->name = "fake http";
  handler->build_response = build_response;
  handler->handle_request = handle_request;
  
  return NGX_CONF_OK;
}

char *fake_http_log_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  fake_http_srv_conf_t *fscf = conf;
  ngx_stream_request_compile_complex_value_t   ccv;
  
  ngx_str_t* value = cf->args->elts;
  ngx_memzero(&ccv, sizeof(ngx_stream_request_compile_complex_value_t));
  ccv.cf = cf;
  ccv.value = &value[1];
  ccv.complex_value = &fscf->logf;
  
  if (ngx_stream_request_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
  }
  
  return NGX_CONF_OK;
}

#define PROTOCOL_RESPONSE_SUCCESS 0
#define PROTOCOL_RESPONSE_FAILED 1

extern ngx_int_t build_response(ngx_stream_request_t* r) {
  fake_http_srv_conf_t *fscf = ngx_stream_get_module_srv_conf(r->session, this_module);
  request_ctx* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  if (r_ctx == NULL) {
    // 未经过handle_request处理的r，说明是 push
    r_ctx = ngx_pcalloc(r->pool, sizeof(request_ctx));
    r_ctx->reqid = 1;
  }
  
  ngx_chain_t* pre = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  pre->buf = ngx_create_temp_buf(r->pool, 10);
  
  *((uint32_t*)pre->buf->last) = htonl(r_ctx->reqid);
  
  pre->buf->last += 4;
  
  ngx_str_t text = ngx_null_string;
  if (ngx_stream_request_complex_value(r, &fscf->logf, &text) != NGX_OK) { \
    r->error = 1;
    ngx_stream_request_set_data(r, "nginx error: fhttp comple value error");
  }
  
  if (r->error == 0) {
    pre->buf->last[0] = PROTOCOL_RESPONSE_SUCCESS;
    ngx_log_error(NGX_LOG_INFO, r->session->connection->log
                  , 0, "FAKE HTTP [OK] %V", &text);
  } else {
    pre->buf->last[0] = PROTOCOL_RESPONSE_FAILED;
    ngx_log_error(NGX_LOG_ERR, r->session->connection->log
                  , 0, "FAKE HTTP [FAILED] %V", &text);
  }
  pre->buf->last++;
  
  pre->next = r->data;
  r->data = pre;
  
  return NGX_OK;
}

extern ngx_int_t handle_request(ngx_stream_request_t* r) {
  ngx_log_t* log = r->session->connection->log;
  
  u_char reqid[4];
  int index = 0;
  ngx_chain_t* last = r->data;
  for (; last != NULL && index < 4; last=last->next) {
    while (last->buf->pos < last->buf->last && index < 4) {
      reqid[index] = last->buf->pos[0];
      last->buf->pos++;
      index++;
    }
  }
  
  request_ctx* ctx = ngx_pcalloc(r->pool, sizeof(request_ctx));
  ngx_stream_request_set_ctx(r, ctx, this_module);
  ctx->reqid = ntohl(*(uint32_t*)reqid);
  ngx_str_str_rbtree_init(&ctx->headers, r->pool, log);
  ngx_log_error(NGX_LOG_DEBUG, r->session->connection->log
                , 0, "reqid = %ud", ctx->reqid);
  
  // 不能让r->data=NULL
  last = r->data;
  while (last != NULL && last->buf->pos == last->buf->last) {
    last = last->next;
  }
  if (last != NULL) {
    r->data = last;
  } else {
    r->data = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    r->data->buf = ngx_create_temp_buf(r->pool, 1);
    last = r->data;
  }
  if (ngx_chain_len(r->data) == 0) {
    return NGX_OK;
  }

  // headers
//  u_char* p = last->buf->pos;
#define LAST_POS (last->buf->pos)
#define LAST_LAST (last->buf->last)
  
  if (*LAST_POS == 0) {
    LAST_POS++;
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0, "no headers");
    return NGX_OK;
  }
  
  ngx_str_t map[2];
  ngx_pool_t* tmp_pool = ngx_create_pool(300, log);
  
  while (1) {
    if (last == NULL) {
      ngx_destroy_pool(tmp_pool);
      return NGX_ERROR;
    }
    if (LAST_POS == LAST_LAST) {
      last = last->next;
      continue;
    }
    if (*LAST_POS == 0) {
      LAST_POS++;
      ngx_destroy_pool(tmp_pool);
      break;
    }
    
    ngx_reset_pool(tmp_pool);
    int i = 0;
		for (i = 0; i < 2; ++i) {
      map[i].len = *LAST_POS;
      ++LAST_POS;
      
      if (LAST_POS + map[i].len < LAST_LAST) {
        map[i].data = LAST_POS;
        LAST_POS += map[i].len;
      } else {
        size_t t_len = 0;
        map[i].data = ngx_pcalloc(tmp_pool, map[i].len);
        while (t_len < map[i].len) {
          if (last == NULL) {
            ngx_destroy_pool(tmp_pool);
            return NGX_ERROR;
          }
          if (LAST_POS == LAST_LAST) {
            last = last->next;
            continue;
          }
          if ((size_t)(LAST_LAST - LAST_POS) < map[i].len - t_len) {
            ngx_memcpy(map[i].data + t_len, LAST_POS
                       , LAST_LAST - LAST_POS);
            t_len += LAST_LAST - LAST_POS;
            LAST_POS = LAST_LAST;
            continue;
          }
          
          ngx_memcpy(map[i].data + t_len, LAST_POS
                     , map[i].len - t_len);
          LAST_POS += map[i].len - t_len;
          t_len = map[i].len;
        }
      }
    }
    
    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0, "header<%V, %V>", &map[0], &map[1]);
    
    ngx_str_str_rbtree_set_value(&ctx->headers, map[0], map[1], 0);
  }
  
  r->data = last;
  if (r->data == NULL) {
    r->data = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    r->data->buf = ngx_create_temp_buf(r->pool, 1);
  }
  
  return NGX_OK;
}

static ngx_int_t
fhttp_header_get_value(ngx_stream_request_t *r
                       , ngx_stream_request_variable_value_t *v
                       , uintptr_t data) {
  request_ctx* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  if (r_ctx == NULL) {
    v->not_found = 1;
    v->valid = 0;
    v->no_cacheable = 1;
    return NGX_OK;
  }
  
  ngx_str_t* key = (ngx_str_t*)data;
  ngx_str_t pref = ngx_string("fhttp_");
  key->data += pref.len;
  key->len -= pref.len;
  
  ngx_str_t value;
  value = ngx_str_str_rbtree_get_value(&r_ctx->headers, *key);
  if (value.len == 0) {
    v->not_found = 1;
    v->valid = 0;
    v->no_cacheable = 1;
    return NGX_OK;
  }
  
  v->data = value.data;
  v->len = (unsigned)value.len;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->valid = 1;
  
  return NGX_OK;
}

static ngx_int_t
fhttp_header_get_reqid(ngx_stream_request_t *r,
                       ngx_stream_request_variable_value_t *v, uintptr_t data) {
  request_ctx* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  if (r_ctx == NULL) {
    v->not_found = 1;
    v->valid = 0;
    v->no_cacheable = 1;
    return NGX_OK;
  }
  
  v->data = ngx_pcalloc(r->pool, 10);
  u_char* p = ngx_sprintf(v->data, "%ud", r_ctx->reqid);
  v->len = (unsigned)(p-v->data);
  v->no_cacheable = 0;
  v->not_found = 0;
  v->valid = 1;
  
  return NGX_OK;
  
}



