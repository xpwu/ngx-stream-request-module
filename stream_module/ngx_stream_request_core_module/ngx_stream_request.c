//
//  ngx_stream_request.c
//  nginx-1.12
//
//  Created by xpwu on 2017/12/16.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#include <ngx_stream_request.h>

extern void ngx_stream_request_regular_data(ngx_stream_request_t* r) {
  if (r->data == NULL) {
    return;
  }
  ngx_chain_t* chain = NULL, *prev=NULL;
  for (chain = r->data->next, prev = r->data
       ; chain != NULL; chain=chain->next) {
    if (ngx_buf_size(chain->buf) == 0) {
      prev->next = chain->next;
    } else {
      prev = chain;
    }
  }
  if (ngx_buf_size(r->data->buf) == 0) {
    r->data = r->data->next;
  }
}

extern void ngx_stream_request_set_data(ngx_stream_request_t* r, char* err_info) {
  ngx_int_t len = ngx_strlen(err_info);

  r->data->buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  r->data->buf = ngx_create_temp_buf(r->pool, len);
  r->data->next = NULL;
  ngx_memcpy(r->data->buf->last, err_info, len);
  r->data->buf->last += len;
}

extern ngx_uint_t ngx_chain_len(ngx_chain_t* chain) {
  ngx_uint_t len = 0;
  for (; chain != NULL; chain = chain->next) {
    len += chain->buf->last - chain->buf->pos;
  }
  return len;
}

extern void ngx_regular_buf(ngx_buf_t* buf) {
  off_t size = ngx_buf_size(buf);
  if (size != 0) {
    ngx_memmove(buf->start, buf->pos, size);
  }
  buf->pos = buf->start;
  buf->last = buf->pos + size;
}

static ngx_int_t is_equal_str(ngx_str_t* str1, ngx_str_t* str2) {
  if (str1->len != str2->len) {
    return 0;
  }
  if (0 != ngx_strncmp(str1->data, str2->data, str2->len)) {
    return 0;
  }
  return 1;
}

extern ngx_array_t* ngx_merge_key_val_array(ngx_pool_t* pool, ngx_array_t* parent
                                            , ngx_array_t* child) {
  
  if (parent == NULL && child == NULL) {
    return NULL;
  }
  ngx_int_t len = 0;
  if (parent != NULL) {
    len += parent->nelts;
  }
  if (child != NULL) {
    len += child->nelts;
  }
  ngx_array_t* re = ngx_array_create(pool, len
                                     , sizeof(ngx_keyval_t));
  
  ngx_array_t* arrs[2];
  arrs[0] = parent;
  arrs[1] = child;
  
  ngx_int_t i = 0;
  for (i = 1; i >= 0; --i) {
    if (arrs[i] == NULL) {
      continue;
    }
    
    ngx_keyval_t* elts = arrs[i]->elts;
    ngx_uint_t j = arrs[i]->nelts;
    for (; j > 0; --j) {
      int contin = 0;
      
      ngx_uint_t k = 0;
      ngx_keyval_t* res = re->elts;
      for (; k < re->nelts; ++k) {
        if (1 == is_equal_str(&res[k].key, &elts[j-1].key)) {
          contin = 1;
          break;
        }
      }
      if (contin) {
        continue;
      }
      res = ngx_array_push(re);
      res->key = elts[j-1].key;
      res->value = elts[j-1].value;
    }
  }
  
  return re;
}



