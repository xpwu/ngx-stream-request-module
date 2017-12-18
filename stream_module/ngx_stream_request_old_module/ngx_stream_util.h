//
//  ngx_stream_util.h
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/12/13.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#ifndef ngx_stream_util_h
#define ngx_stream_util_h

#include <ngx_config.h>
#include <ngx_core.h>

extern void ngx_regular_buf(ngx_buf_t* buf);
extern ngx_uint_t ngx_chain_len(ngx_chain_t* chain);
extern ngx_array_t* ngx_merge_key_val_array(ngx_pool_t* pool, ngx_array_t* parent
                                , ngx_array_t* child);

#endif /* ngx_stream_util_h */
