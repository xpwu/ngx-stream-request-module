//
//  ngx_stream_variable_module.h
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/9.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#ifndef ngx_stream_variable_module_h
#define ngx_stream_variable_module_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

extern ngx_str_t ngx_stream_get_variable_value(ngx_stream_session_t* s
                                               , ngx_str_t variable_name);
extern void ngx_stream_set_variable_value(ngx_stream_session_t* s
                                          , ngx_str_t variable_name
                                          , ngx_str_t variable_value
                                          , ngx_int_t force_rewrite);

#endif /* ngx_stream_variable_module_h */
