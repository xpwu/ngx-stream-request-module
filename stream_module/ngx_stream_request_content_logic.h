//
//  ngx_stream_request_content_logic.h
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/11/17.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#ifndef ngx_stream_request_content_logic_h
#define ngx_stream_request_content_logic_h
/*
 * content protocol:
 *    request ---
 *      reqid | data
 *        reqid: 4 bytes, net order;
 *
 *    response ---
 *      reqid | status | data
 *        reqid: 4 bytes, net order;
 *        status: 1 byte, 0---success, 1---failed
 *        data: if status==success, data=<app data>
 *              if status==failed, data=<error reason>
 *
 */

#include "ngx_stream_request_core_module.h"

extern void
ngx_stream_request_parse_content_protocol(ngx_stream_request_t* r);

extern void
ngx_stream_request_build_content_protocol(ngx_stream_request_t* r);


#endif /* ngx_stream_request_content_logic_h */
