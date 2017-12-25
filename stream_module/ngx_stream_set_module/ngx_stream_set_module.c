//
//  ngx_stream_set_module.c
//  nginx-1.12
//
//  Created by xpwu on 2017/12/17.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_set_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_core_module

static char * ngx_stream_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_set_get_variable (ngx_stream_session_t *s,
                                         ngx_stream_variable_value_t *
                                             , uintptr_t data);

static ngx_command_t  ngx_stream_set_commands[] = {
  
  { ngx_string("set"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
    ngx_stream_set,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_set_module_ctx = {
  NULL,                                   /* preconfiguration */
  NULL,                                  /* postconfiguration */
  
  NULL,                                  /* create main configuration */
  NULL,                                  /* init main configuration */
  
  NULL,                                  /* create server configuration */
  NULL                                   /* merge server configuration */
};

ngx_module_t  ngx_stream_set_module = {
  NGX_MODULE_V1,
  &ngx_stream_set_module_ctx,           /* module context */
  ngx_stream_set_commands,              /* module directives */
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

static char * ngx_stream_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_str_t                           *value;
  ngx_stream_compile_complex_value_t   ccv;
  ngx_stream_variable_t *v;
  
  value = cf->args->elts;
  
  ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
  
  ccv.cf = cf;
  ccv.value = &value[2];
  ccv.complex_value = ngx_pcalloc(cf->pool, sizeof(ngx_stream_complex_value_t));
  if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
  }
  
  ngx_str_t* var = &value[1];
  if (var->data[0] == '$') {
    var->data += 1;
    var->len -= 1;
  }
  v = ngx_stream_add_variable(cf, var, 0);
  
  if (v == NULL) {
    return NGX_CONF_ERROR;
  }
  v->data = (uintptr_t)ccv.complex_value;
  v->flags = 0;
  v->get_handler =ngx_stream_set_get_variable;
  
  return NGX_CONF_OK;
}

static ngx_int_t ngx_stream_set_get_variable (ngx_stream_session_t *s,
                                              ngx_stream_variable_value_t *value
                                              , uintptr_t data) {
  ngx_stream_complex_value_t *complex = (ngx_stream_complex_value_t*)data;
  ngx_str_t text;
  
  if (ngx_stream_complex_value(s, complex, &text) != NGX_OK) {
    return NGX_ERROR;
  }
  
  value->len = (unsigned)text.len;
  value->data = text.data;
  value->valid = (value->data!=NULL)?1:0;
  value->not_found = (value->len==0&&value->data==NULL)?1:0;
  value->no_cacheable = (value->len==0||value->data==NULL)?1:0;
  
  return NGX_OK;
}

