//
//  ngx_stream_request_content_logic.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/11/17.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include "ngx_stream_request_content_logic.h"

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

extern void
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
                  , 0, "websocket response state=success");
  } else {
    pre->buf->last[0] = PROTOCOL_RESPONSE_FAILED;
    ngx_log_error(NGX_LOG_INFO, r->session->connection->log
                  , 0, "websocket response state=failed");
  }
  pre->buf->last++;
  
  pre->next = r->data;
  r->data = pre;
}

extern void
ngx_stream_request_parse_content_protocol(ngx_stream_request_t* r) {
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
                , 0, "websocket reqid = %ud", ctx->reqid);
}


//#if (NGX_STREAM_SSL)
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





