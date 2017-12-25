//
//  ngx_stream_request_push_module.h
//  nginx-1.12
//
//  Created by xpwu on 2017/12/23.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#ifndef ngx_stream_request_push_module_h
#define ngx_stream_request_push_module_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>


// 通过r->data的buffer位置与 ctx->msg的buffer位置 自动判断是否需要重新分配空间
// 具体见 need_copy_data 的实现

// NGX_OK; NGX_ERROR; NGX_AGAIN;
// 如果返回NGX_AGAIN，在后续流程中需要调用
// ngx_stream_request_push_back_src_process 把request返回原进程
typedef ngx_int_t
(*ngx_stream_request_push_dist_hander)(ngx_stream_request_t*);

// NGX_OK; NGX_ERROR; NGX_AGAIN
extern ngx_int_t
ngx_stream_request_push_to_dist_process(ngx_stream_request_t*,
                                        ngx_stream_request_push_dist_hander);

extern void
ngx_stream_request_push_back_src_process(ngx_stream_request_t*);


#endif /* ngx_stream_request_push_module_h */
