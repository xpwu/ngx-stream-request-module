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
