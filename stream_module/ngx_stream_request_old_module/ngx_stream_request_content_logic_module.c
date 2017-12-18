//
//  ngx_stream_request_content_logic.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/11/17.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include "ngx_stream_request_content_logic.h"
#include "ngx_stream_util.h"

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_content_logic_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

static ngx_command_t  ngx_stream_content_commands[] = {
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_content_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  NULL,   /* create server configuration */
  NULL     /* merge server configuration */
};


ngx_module_t  ngx_stream_request_content_logic_module = {
  NGX_MODULE_V1,
  &ngx_stream_content_module_ctx,           /* module context */
  ngx_stream_content_commands,              /* module directives */
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
} request_ctx;

#define PROTOCOL_RESPONSE_SUCCESS 0
#define PROTOCOL_RESPONSE_FAILED 1

extern ngx_int_t
ngx_stream_request_build_content_protocol(ngx_stream_request_t* r) {
  request_ctx* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  ngx_chain_t* pre = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  pre->buf = ngx_create_temp_buf(r->pool, 10);
  
  const uint32_t pushID = 1; // need equal client
  if (r->type == STREAM_REQUEST_PUSH) {
    *((uint32_t*)pre->buf->last) = htonl(pushID);
  } else {
    *((uint32_t*)pre->buf->last) = htonl(r_ctx->reqid);
  }
  pre->buf->last += 4;
  
  if (r->response_status == RESPONSE_STATUS_SUCCESS) {
    pre->buf->last[0] = PROTOCOL_RESPONSE_SUCCESS;
    ngx_log_error(NGX_LOG_INFO, r->session->connection->log
                  , 0, "response state=success");
  } else {
    pre->buf->last[0] = PROTOCOL_RESPONSE_FAILED;
    ngx_log_error(NGX_LOG_INFO, r->session->connection->log
                  , 0, "response state=failed");
  }
  pre->buf->last++;
  
  pre->next = r->data;
  r->data = pre;
  
  return NGX_OK;
}

extern ngx_int_t
ngx_stream_request_parse_content_protocol(ngx_stream_request_t* r) {
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
  ngx_log_error(NGX_LOG_INFO, r->session->connection->log
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
    
    ngx_stream_request_set_header(r, map[0], map[1]);
  }
  
  r->data = last;
  if (r->data == NULL) {
    r->data = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    r->data->buf = ngx_create_temp_buf(r->pool, 1);
  }
  
  return NGX_OK;
}

