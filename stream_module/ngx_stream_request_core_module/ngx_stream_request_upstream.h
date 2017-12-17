//
//  ngx_stream_request_upstream.h
//  nginx-1.12
//
//  Created by xpwu on 2017/12/16.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#ifndef ngx_stream_request_upstream_h
#define ngx_stream_request_upstream_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>

struct ngx_stream_request_upstream_s{
  ngx_stream_upstream_t upstream;
  void (*upstream_connected)(ngx_stream_request_t*);
  void (*upstream_connect_failed)(ngx_stream_request_t*, char* reason);
} ;

extern void ngx_stream_request_upstream_connect(ngx_stream_request_t *r);


#endif /* ngx_stream_request_upstream_h */
