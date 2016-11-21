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
 */

#include "ngx_stream_request_core_module.h"

extern ngx_int_t
ngx_stream_request_parse_content_protocol(ngx_stream_request_t* r);

extern ngx_int_t
ngx_stream_request_build_content_protocol(ngx_stream_request_t* r);


#endif /* ngx_stream_request_content_logic_h */
