//
//  ngx_stream_request_core_module.c
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/6.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include "ngx_stream_request_core_module.h"

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_core_module

static void ngx_stream_request_core_handler(ngx_stream_session_t *s);
//static u_char *ngx_stream_request_core_log_error(ngx_log_t *log, u_char *buf,
//                                          size_t len);

static void *ngx_stream_request_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_request_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_stream_request_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_request_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
                                             void *child);
static char *ngx_stream_request_core_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *ngx_stream_request_core_bind(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static u_char* ngx_stream_request_log_handler(ngx_log_t *log, u_char *buf, size_t len);

static void ngx_stream_close_request(ngx_stream_request_t*);


#if (NGX_STREAM_SSL)

static char *ngx_stream_request_proxy_ssl_password_file(ngx_conf_t *cf,
                                                ngx_command_t *cmd, void *conf);
static void ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s);
static void ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc);
static ngx_int_t ngx_stream_proxy_ssl_name(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_proxy_set_ssl(ngx_conf_t *cf,
                                          ngx_stream_proxy_srv_conf_t *pscf);

static ngx_conf_bitmask_t  ngx_stream_proxy_ssl_protocols[] = {
  { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
  { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
  { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
  { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
  { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
  { ngx_null_string, 0 }
};

#endif

static void empty_handler(ngx_event_t *ev){}

typedef struct {
  ngx_queue_t wait_send;
  ngx_queue_t processing;
  
  ngx_int_t wait_send_cnt;
  ngx_int_t processing_cnt;
  ngx_int_t request_cnt;
  
  ngx_stream_cleanup_t* cleanups;
}request_core_ctx_t;

static ngx_command_t  ngx_stream_request_core_commands[] = {
  
  { ngx_string("session_request"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    ngx_stream_request_core_pass,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  { ngx_string("request_proxy_bind"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_stream_request_core_bind,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  { ngx_string("request_proxy_connect_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, connect_timeout),
    NULL },
  
  { ngx_string("request_proxy_next_upstream"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, next_upstream),
    NULL },
  
  { ngx_string("request_proxy_next_upstream_tries"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, next_upstream_tries),
    NULL },
  
  { ngx_string("request_proxy_next_upstream_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, next_upstream_timeout),
    NULL },
  
  { ngx_string("request_send_to_proxy_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, send_timeout),
    NULL},
  
  { ngx_string("request_receive_from_proxy_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, receive_timeout),
    NULL},
  
  { ngx_string("request_proxy_response_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, response_timeout),
    NULL},
  
  // ------- client ----------
  
  { ngx_string("client_handshake_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, handshake_timeout),
    NULL},
  
  { ngx_string("request_receive_from_client_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, request_timeout),
    NULL},
  
  { ngx_string("client_heartbeat"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, heartbeat),
    NULL},
  
  { ngx_string("request_send_to_client_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, send_to_client_timeout),
    NULL},
  
  { ngx_string("request_failed_log_to_client"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, send_error_log_to_client),
    NULL},
  
  // ------- client ----------
  
#if (NGX_STREAM_SSL)
  
  { ngx_string("request_proxy_ssl"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_enable),
    NULL },
  
  { ngx_string("request_proxy_ssl_session_reuse"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_session_reuse),
    NULL },
  
  { ngx_string("request_proxy_ssl_protocols"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
    ngx_conf_set_bitmask_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_protocols),
    &ngx_stream_proxy_ssl_protocols },
  
  { ngx_string("request_proxy_ssl_ciphers"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_ciphers),
    NULL },
  
  { ngx_string("request_proxy_ssl_name"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_name),
    NULL },
  
  { ngx_string("request_proxy_ssl_server_name"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_server_name),
    NULL },
  
  { ngx_string("request_proxy_ssl_verify"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_verify),
    NULL },
  
  { ngx_string("request_proxy_ssl_verify_depth"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_verify_depth),
    NULL },
  
  { ngx_string("request_proxy_ssl_trusted_certificate"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_trusted_certificate),
    NULL },
  
  { ngx_string("request_proxy_ssl_crl"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_crl),
    NULL },
  
  { ngx_string("request_proxy_ssl_certificate"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_certificate),
    NULL },
  
  { ngx_string("request_proxy_ssl_certificate_key"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_core_srv_conf_t, ssl_certificate_key),
    NULL },
  
  { ngx_string("request_proxy_ssl_password_file"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_stream_request_proxy_ssl_password_file,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
#endif
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_request_core_module_ctx = {
  NULL,                                  /* postconfiguration */
  
  ngx_stream_request_core_create_main_conf,     /* create main configuration */
  ngx_stream_request_core_init_main_conf,       /* init main configuration */
  
  ngx_stream_request_core_create_srv_conf,      /* create server configuration */
  ngx_stream_request_core_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_stream_request_core_module = {
  NGX_MODULE_V1,
  &ngx_stream_request_core_module_ctx,          /* module context */
  ngx_stream_request_core_commands,             /* module directives */
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

#pragma mark - conf

static void *ngx_stream_request_core_create_main_conf(ngx_conf_t *cf) {
  ngx_stream_request_core_main_conf_t  *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_request_core_main_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  return conf;
}

static char *ngx_stream_request_core_init_main_conf(ngx_conf_t *cf, void *conf) {
  ngx_stream_request_core_main_conf_t  *cmcf = conf;
  
  ngx_array_init(&cmcf->session_initializers, cf->pool, 2, sizeof(void (*)(ngx_stream_session_t*)) );
  
  return NGX_CONF_OK;
}

static void *
ngx_stream_request_core_create_srv_conf(ngx_conf_t *cf)
{
  ngx_stream_request_core_srv_conf_t  *conf;
  
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_request_core_srv_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  
  /*
   * set by ngx_pcalloc():
   *
   *     conf->ssl_ciphers = { 0, NULL };
   *     conf->ssl_name = { 0, NULL };
   *     conf->ssl_trusted_certificate = { 0, NULL };
   *     conf->ssl_crl = { 0, NULL };
   *     conf->ssl_certificate = { 0, NULL };
   *     conf->ssl_certificate_key = { 0, NULL };
   *     conf->send_error_log_to_client = 0;
   *
   *     conf->ssl = NULL;
   *     conf->upstream = NULL;
   *
   *     conf->init_parser = NULL;
   *     conf->parse_request = NULL;
   *     conf->build_response = NULL;
   *     conf->handle_request = NULL;
   *
   */
  
  conf->connect_timeout = NGX_CONF_UNSET_MSEC;
  conf->send_to_client_timeout = NGX_CONF_UNSET_MSEC;
  conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
  conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
  conf->next_upstream = NGX_CONF_UNSET;
  conf->local = NGX_CONF_UNSET_PTR;
  conf->send_error_log_to_client = NGX_CONF_UNSET;
  
  conf->handshake_timeout = NGX_CONF_UNSET_MSEC;
  conf->heartbeat = NGX_CONF_UNSET_MSEC;
  conf->request_timeout = NGX_CONF_UNSET_MSEC;
  
  conf->receive_timeout = NGX_CONF_UNSET_MSEC;
  conf->send_timeout = NGX_CONF_UNSET_MSEC;
  conf->response_timeout = NGX_CONF_UNSET_MSEC;
  
#if (NGX_STREAM_SSL)
  conf->ssl_enable = NGX_CONF_UNSET;
  conf->ssl_session_reuse = NGX_CONF_UNSET;
  conf->ssl_server_name = NGX_CONF_UNSET;
  conf->ssl_verify = NGX_CONF_UNSET;
  conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
  conf->ssl_passwords = NGX_CONF_UNSET_PTR;
#endif
  
  return conf;
}


static char *
ngx_stream_request_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_stream_request_core_srv_conf_t *prev = parent;
  ngx_stream_request_core_srv_conf_t *conf = child;
  
  ngx_conf_merge_msec_value(conf->connect_timeout,
                            prev->connect_timeout, 60000);
  
  ngx_conf_merge_msec_value(conf->send_to_client_timeout,
                            prev->send_to_client_timeout, 10000);
  
  ngx_conf_merge_msec_value(conf->handshake_timeout, prev->handshake_timeout, 30000);
  ngx_conf_merge_msec_value(conf->heartbeat, prev->heartbeat, 4*60000);
  ngx_conf_merge_msec_value(conf->request_timeout, prev->request_timeout, 10000);
  
  ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                            prev->next_upstream_timeout, 0);
  
  ngx_conf_merge_uint_value(conf->next_upstream_tries,
                            prev->next_upstream_tries, 0);
  
  ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);
  
  ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);
  
  ngx_conf_merge_value(conf->send_error_log_to_client
                       , prev->send_error_log_to_client, 0);
  
  ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 5000);
  ngx_conf_merge_msec_value(conf->receive_timeout, prev->receive_timeout, 5000);
  ngx_conf_merge_msec_value(conf->response_timeout, prev->response_timeout, 10000);
  
#if (NGX_STREAM_SSL)
  
  ngx_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);
  
  ngx_conf_merge_value(conf->ssl_session_reuse,
                       prev->ssl_session_reuse, 1);
  
  ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                               (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                                |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));
  
  ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");
  
  ngx_conf_merge_str_value(conf->ssl_name, prev->ssl_name, "");
  
  ngx_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);
  
  ngx_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);
  
  ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                            prev->ssl_verify_depth, 1);
  
  ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                           prev->ssl_trusted_certificate, "");
  
  ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
  
  ngx_conf_merge_str_value(conf->ssl_certificate,
                           prev->ssl_certificate, "");
  
  ngx_conf_merge_str_value(conf->ssl_certificate_key,
                           prev->ssl_certificate_key, "");
  
  ngx_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);
  
  if (conf->ssl_enable && ngx_stream_proxy_set_ssl(cf, conf) != NGX_OK) {
    return NGX_CONF_ERROR;
  }
  
#endif
  
  return NGX_CONF_OK;
}

static char *
ngx_stream_request_core_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_stream_request_core_srv_conf_t *pscf = conf;
  
  if (pscf->upstream) {
    return "is duplicate";
  }
  
  ngx_stream_core_srv_conf_t  *cscf;
  cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
  cscf->handler = ngx_stream_request_core_handler;
  
  // upstream 由具体的代理协议设置
  
  return NGX_CONF_OK;
}


static char *
ngx_stream_request_core_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_stream_request_core_srv_conf_t *pscf = conf;
  
  ngx_int_t   rc;
  ngx_str_t  *value;
  
  if (pscf->local != NGX_CONF_UNSET_PTR) {
    return "is duplicate";
  }
  
  value = cf->args->elts;
  
  if (ngx_strcmp(value[1].data, "off") == 0) {
    pscf->local = NULL;
    return NGX_CONF_OK;
  }
  
  pscf->local = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
  if (pscf->local == NULL) {
    return NGX_CONF_ERROR;
  }
  
  rc = ngx_parse_addr(cf->pool, pscf->local, value[1].data, value[1].len);
  
  switch (rc) {
    case NGX_OK:
      pscf->local->name = value[1];
      return NGX_CONF_OK;
      
    case NGX_DECLINED:
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid address \"%V\"", &value[1]);
      /* fall through */
      
    default:
      return NGX_CONF_ERROR;
  }
}

static u_char* ngx_stream_request_log_handler(ngx_log_t *log, u_char *buf, size_t len) {
  ngx_stream_session_t* s = log->data;
  u_char* p = buf;
  request_core_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  p = ngx_snprintf(p, len,
                   ", session_ptr=%p, all_request=%ud"
                   ", wait_send_cnt=%ud, processing_cnt=%ud\n"
                   , s, ctx->request_cnt, ctx->wait_send_cnt
                   , ctx->processing_cnt);
  return p;
}

#if (NGX_STREAM_SSL)

static char *
ngx_stream_request_proxy_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf)
{
  ngx_stream_request_core_srv_conf_t *pscf = conf;
  
  ngx_str_t  *value;
  
  if (pscf->ssl_passwords != NGX_CONF_UNSET_PTR) {
    return "is duplicate";
  }
  
  value = cf->args->elts;
  
  pscf->ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);
  
  if (pscf->ssl_passwords == NULL) {
    return NGX_CONF_ERROR;
  }
  
  return NGX_CONF_OK;
}


static void
ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s)
{
  ngx_int_t                     rc;
  ngx_connection_t             *pc;
  ngx_stream_upstream_t        *u;
  ngx_stream_request_core_srv_conf_t  *pscf;
  ngx_stream_session_t *s = r->session;
  
  u = r->upstream;
  
  pc = u->peer.connection;
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  if (ngx_ssl_create_connection(pscf->ssl, pc, NGX_SSL_BUFFER|NGX_SSL_CLIENT)
      != NGX_OK)
  {
    ngx_stream_request_failed(r, "request proxy ssl create connection error");
    return;
  }
  
  if (pscf->ssl_server_name || pscf->ssl_verify) {
    if (ngx_stream_proxy_ssl_name(r) != NGX_OK) {
      ngx_stream_request_failed(r, "request proxy ssl name error");
      return;
    }
  }
  
  if (pscf->ssl_session_reuse) {
    if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
      ngx_stream_request_failed(r, "request proxy ssl set session error");
      return;
    }
  }
  
  s->connection->log->action = "SSL handshaking to upstream";
  
  rc = ngx_ssl_handshake(pc);
  
  if (rc == NGX_AGAIN) {
    
    if (!pc->write->timer_set) {
      ngx_add_timer(pc->write, pscf->connect_timeout);
    }
    
    pc->ssl->handler = ngx_stream_proxy_ssl_handshake;
    return;
  }
  
  ngx_stream_proxy_ssl_handshake(pc);
}


static void
ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc)
{
  long                          rc;
  ngx_stream_session_t         *s;
  ngx_stream_upstream_t        *u;
  ngx_stream_request_core_srv_conf_t  *pscf;
  
  s = pc->data;
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  if (pc->ssl->handshaked) {
    
    if (pscf->ssl_verify) {
      rc = SSL_get_verify_result(pc->ssl->connection);
      
      if (rc != X509_V_OK) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "upstream SSL certificate verify error: (%l:%s)",
                      rc, X509_verify_cert_error_string(rc));
        goto failed;
      }
      
      u = s->upstream;
      
      if (ngx_ssl_check_host(pc, &u->ssl_name) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "upstream SSL certificate does not match \"%V\"",
                      &u->ssl_name);
        goto failed;
      }
    }
    
    if (pscf->ssl_session_reuse) {
      u = s->upstream;
      u->peer.save_session(&u->peer, u->peer.data);
    }
    
    if (pc->write->timer_set) {
      ngx_del_timer(pc->write);
    }
    
    ngx_stream_proxy_init_upstream(s);
    
    return;
  }
  
failed:
  
  ngx_stream_proxy_next_upstream(s);
}


static ngx_int_t
ngx_stream_proxy_ssl_name(ngx_stream_request_t *r)
{
  u_char                       *p, *last;
  ngx_str_t                     name;
  ngx_stream_upstream_t        *u;
  ngx_stream_request_core_srv_conf_t  *pscf;
  ngx_stream_session_t *s = r->session;
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  u = r->upstream;
  
  name = pscf->ssl_name;
  
  if (name.len == 0) {
    name = pscf->upstream->host;
  }
  
  if (name.len == 0) {
    goto done;
  }
  
  /*
   * ssl name here may contain port, strip it for compatibility
   * with the http module
   */
  
  p = name.data;
  last = name.data + name.len;
  
  if (*p == '[') {
    p = ngx_strlchr(p, last, ']');
    
    if (p == NULL) {
      p = name.data;
    }
  }
  
  p = ngx_strlchr(p, last, ':');
  
  if (p != NULL) {
    name.len = p - name.data;
  }
  
  if (!pscf->ssl_server_name) {
    goto done;
  }
  
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  
  /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */
  
  if (name.len == 0 || *name.data == '[') {
    goto done;
  }
  
  if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
    goto done;
  }
  
  /*
   * SSL_set_tlsext_host_name() needs a null-terminated string,
   * hence we explicitly null-terminate name here
   */
  
  p = ngx_pnalloc(s->connection->pool, name.len + 1);
  if (p == NULL) {
    return NGX_ERROR;
  }
  
  (void) ngx_cpystrn(p, name.data, name.len + 1);
  
  name.data = p;
  
  ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                 "upstream SSL server name: \"%s\"", name.data);
  
  if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection, name.data)
      == 0)
  {
    ngx_ssl_error(NGX_LOG_ERR, s->connection->log, 0,
                  "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
    return NGX_ERROR;
  }
  
#endif
  
done:
  
  u->ssl_name = name;
  
  return NGX_OK;
}

static ngx_int_t
ngx_stream_proxy_set_ssl(ngx_conf_t *cf, ngx_stream_request_core_srv_conf_t *pscf)
{
  ngx_pool_cleanup_t  *cln;
  
  pscf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
  if (pscf->ssl == NULL) {
    return NGX_ERROR;
  }
  
  pscf->ssl->log = cf->log;
  
  if (ngx_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != NGX_OK) {
    return NGX_ERROR;
  }
  
  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NGX_ERROR;
  }
  
  cln->handler = ngx_ssl_cleanup_ctx;
  cln->data = pscf->ssl;
  
  if (pscf->ssl_certificate.len) {
    
    if (pscf->ssl_certificate_key.len == 0) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "no \"proxy_ssl_certificate_key\" is defined "
                    "for certificate \"%V\"", &pscf->ssl_certificate);
      return NGX_ERROR;
    }
    
    if (ngx_ssl_certificate(cf, pscf->ssl, &pscf->ssl_certificate,
                            &pscf->ssl_certificate_key, pscf->ssl_passwords)
        != NGX_OK)
    {
      return NGX_ERROR;
    }
  }
  
  if (SSL_CTX_set_cipher_list(pscf->ssl->ctx,
                              (const char *) pscf->ssl_ciphers.data)
      == 0)
  {
    ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                  "SSL_CTX_set_cipher_list(\"%V\") failed",
                  &pscf->ssl_ciphers);
    return NGX_ERROR;
  }
  
  if (pscf->ssl_verify) {
    if (pscf->ssl_trusted_certificate.len == 0) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
      return NGX_ERROR;
    }
    
    if (ngx_ssl_trusted_certificate(cf, pscf->ssl,
                                    &pscf->ssl_trusted_certificate,
                                    pscf->ssl_verify_depth)
        != NGX_OK)
    {
      return NGX_ERROR;
    }
    
    if (ngx_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != NGX_OK) {
      return NGX_ERROR;
    }
  }
  
  return NGX_OK;
}

#endif

#pragma mark - handler

static void ngx_stream_request_proxy_connect(ngx_stream_request_t *r);
static void ngx_stream_request_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_request_core_test_connect(ngx_connection_t *c);
static void ngx_stream_request_core_next_upstream(ngx_stream_request_t *r);
static void ngx_stream_proxy_init_upstream(ngx_stream_request_t *r);

#pragma mark -impl-

static ngx_int_t
ngx_stream_request_core_test_connect(ngx_connection_t *c)
{
  int        err;
  socklen_t  len;
  
#if (NGX_HAVE_KQUEUE)
  
  if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
    err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;
    
    if (err) {
      (void) ngx_connection_error(c, err,
                                  "kevent() reported that connect() failed");
      return NGX_ERROR;
    }
    
  } else
#endif
  {
    err = 0;
    len = sizeof(int);
    
    /*
     * BSDs and Linux return 0 and set a pending error in err
     * Solaris returns -1 and sets errno
     */
    
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
        == -1)
    {
      err = ngx_socket_errno;
    }
    
    if (err) {
      (void) ngx_connection_error(c, err, "connect() failed");
      return NGX_ERROR;
    }
  }
  
  return NGX_OK;
}

static void
ngx_stream_request_core_next_upstream(ngx_stream_request_t *r)
{
  ngx_msec_t                    timeout;
  ngx_connection_t             *pc;
  ngx_stream_upstream_t        *u;
  ngx_stream_request_core_srv_conf_t  *pscf;
  
  ngx_log_debug0(NGX_LOG_DEBUG_STREAM, r->session->connection->log, 0,
                 "stream proxy next upstream");
  
  u = r->upstream;
  
  if (u->peer.sockaddr) {
    u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
    u->peer.sockaddr = NULL;
  }
  
  pscf = ngx_stream_get_module_srv_conf(r->session, this_module);
  
  timeout = pscf->next_upstream_timeout;
  
  if (u->peer.tries == 0
      || !pscf->next_upstream
      || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
  {
    ngx_stream_request_failed(r, "has not upstream");
    return;
  }
  
  pc = u->peer.connection;
  
  if (pc) {
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->session->connection->log, 0,
                   "close proxy upstream connection: %d", pc->fd);
    
#if (NGX_STREAM_SSL)
    if (pc->ssl) {
      pc->ssl->no_wait_shutdown = 1;
      pc->ssl->no_send_shutdown = 1;
      
      (void) ngx_ssl_shutdown(pc);
    }
#endif
    
    ngx_close_connection(pc);
    u->peer.connection = NULL;
  }
  
  ngx_stream_request_proxy_connect(r);
}

static void
ngx_stream_request_proxy_connect(ngx_stream_request_t *r)
{
  ngx_int_t                     rc;
  ngx_connection_t             *c, *pc;
  ngx_stream_upstream_t        *u;
  ngx_stream_request_core_srv_conf_t  *pscf;
  ngx_stream_session_t* s;
  
  s = r->session;
  c = s->connection;
  
  c->log->action = "connecting to upstream";
  
  u = r->upstream;
  
  rc = ngx_event_connect_peer(&u->peer);
  
  ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);
  
  if (rc == NGX_ERROR) {
    ngx_stream_request_failed(r, "connect upsteam peer error");
    return;
  }
  
  if (rc == NGX_BUSY) {
    ngx_stream_request_failed(r, "no live upstreams");
    return;
  }
  
  if (rc == NGX_DECLINED) {
    ngx_stream_request_core_next_upstream(r);
    return;
  }
  
  /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */
  
  pc = u->peer.connection;
  
  pc->data = r;
  pc->log = c->log;
  pc->pool = r->pool;
  pc->read->log = c->log;
  pc->write->log = c->log;
  
  if (rc != NGX_AGAIN) {
    ngx_stream_proxy_init_upstream(r);
    return;
  }
  
  pc->read->handler = ngx_stream_request_proxy_connect_handler;
  pc->write->handler = ngx_stream_request_proxy_connect_handler;
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  ngx_add_timer(pc->write, pscf->connect_timeout);
}

static void
ngx_stream_proxy_init_upstream(ngx_stream_request_t *r)
{
  int                           tcp_nodelay;
//  u_char                       *p;
  ngx_connection_t             *c, *pc;
  ngx_log_handler_pt            handler;
  ngx_stream_upstream_t        *u;
  ngx_stream_core_srv_conf_t   *cscf;
  ngx_stream_request_core_srv_conf_t  *pscf;
  ngx_stream_session_t* s = r->session;
  
  u = r->upstream;
  pc = u->peer.connection;
  
  cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
  
  if (pc->type == SOCK_STREAM
      && cscf->tcp_nodelay
      && pc->tcp_nodelay == NGX_TCP_NODELAY_UNSET)
  {
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "tcp_nodelay");
    
    tcp_nodelay = 1;
    
    if (setsockopt(pc->fd, IPPROTO_TCP, TCP_NODELAY,
                   (const void *) &tcp_nodelay, sizeof(int)) == -1)
    {
      ngx_connection_error(pc, ngx_socket_errno,
                           "setsockopt(TCP_NODELAY) failed");
      ngx_stream_request_core_next_upstream(r);
      return;
    }
    
    pc->tcp_nodelay = NGX_TCP_NODELAY_SET;
  }
  
  /*
//  if (u->proxy_protocol) {
//    if (ngx_stream_proxy_send_proxy_protocol(s) != NGX_OK) {
//      return;
//    }
//    
//    u->proxy_protocol = 0;
//  }
   */
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
#if (NGX_STREAM_SSL)
  if (pc->type == SOCK_STREAM && pscf->ssl && pc->ssl == NULL) {
    ngx_stream_proxy_ssl_init_connection(r);
    return;
  }
#endif
  
  c = s->connection;
  
  if (c->log->log_level >= NGX_LOG_INFO) {
    ngx_str_t  str;
    u_char     addr[NGX_SOCKADDR_STRLEN];
    
    str.len = NGX_SOCKADDR_STRLEN;
    str.data = addr;
    
    if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
      handler = c->log->handler;
      c->log->handler = NULL;
      
      ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "%sproxy %V connected to %V",
                    pc->type == SOCK_DGRAM ? "udp " : "",
                    &str, u->peer.name);
      
      c->log->handler = handler;
    }
  }
  
//  c->log->action = "proxying connection";
  /*
//  if (u->upstream_buf.start == NULL) {
//    p = ngx_pnalloc(c->pool, pscf->buffer_size);
//    if (p == NULL) {
//      ngx_stream_proxy_finalize(s, NGX_ERROR);
//      return;
//    }
//    
//    u->upstream_buf.start = p;
//    u->upstream_buf.end = p + pscf->buffer_size;
//    u->upstream_buf.pos = p;
//    u->upstream_buf.last = p;
//  }
  
//  if (c->type == SOCK_DGRAM) {
//    s->received = c->buffer->last - c->buffer->pos;
//    u->downstream_buf = *c->buffer;
//    
//    if (pscf->responses == 0) {
//      pc->read->ready = 0;
//      pc->read->eof = 1;
//    }
//  }
  */
  u->connected = 1;
  
  pc->read->handler = empty_handler;
  pc->write->handler = empty_handler;
  
  if (pscf->init_proxy_handler) {
    pscf->init_proxy_handler(r);
  }
  
  if (pscf->proxy_handle_request != NULL) {
    pscf->proxy_handle_request(r);
  }
}

static void
ngx_stream_request_proxy_connect_handler(ngx_event_t *ev)
{
  ngx_connection_t      *c;
  ngx_stream_session_t  *s;
  ngx_stream_request_t* r;
  
  c = ev->data;
  r = c->data;
  s = r->session;
  
  if (ev->timedout) {
    ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
    ngx_stream_request_core_next_upstream(r);
    return;
  }
  
  if (ev->timer_set) {
    ngx_del_timer(ev);
  }
  
  ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                 "stream proxy connect upstream");
  
  if (ngx_stream_request_core_test_connect(c) != NGX_OK) {
    ngx_stream_request_core_next_upstream(r);
    return;
  }
  
  ngx_stream_proxy_init_upstream(r);
}

extern void ngx_stream_request_failed(ngx_stream_request_t *r, char* reason) {
  ngx_stream_request_core_srv_conf_t  *pscf;
  pscf = ngx_stream_get_module_srv_conf(r->session, this_module);
  
  ngx_log_error(NGX_LOG_ERR, r->session->connection->log
                , 0, "request failed because %s", reason);
  r->response_status = RESPONSE_STATUS_FAILED;
  
  if (pscf->send_error_log_to_client) {
    char* p = reason;
    while (*p != '\0') {
      p++;
    }
    r->data->buf = ngx_create_temp_buf(r->pool, p-reason);
    r->data->next = NULL;
    ngx_memcpy(r->data->buf->last, reason, p-reason);
    r->data->buf->last = r->data->buf->last + (p-reason);
  }else {
    r->data->buf = ngx_create_temp_buf(r->pool, 1);
    r->data->next = NULL;
  }
  
  handle_request_done(r);
}

static void ngx_stream_read_handler(ngx_event_t *ev);
static void ngx_stream_write_handler(ngx_event_t *ev);

static void ngx_stream_request_core_handler(ngx_stream_session_t *s) {
  ngx_stream_request_core_srv_conf_t  *pscf;
  ngx_connection_t* c = s->connection;
  request_core_ctx_t* ctx = NULL;
  
  ctx = ngx_pcalloc(c->pool, sizeof(request_core_ctx_t));
  ngx_queue_init(&ctx->processing);
  ngx_queue_init(&ctx->wait_send);
  ngx_stream_set_ctx(s, ctx, this_module);
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  ngx_stream_request_core_main_conf_t* cmcf;
  cmcf = ngx_stream_get_module_main_conf(s, this_module);
  void (**initer)(ngx_stream_session_t*) = cmcf->session_initializers.elts;
  for (ngx_uint_t i = 0; i < cmcf->session_initializers.nelts; ++i) {
    initer[i](s);
  }
  
  if (pscf->init_parser) {
    pscf->init_parser(s);
  }
  
  s->log_handler = ngx_stream_request_log_handler;
  c->log->action = " process session ";
  
  c->read->handler = ngx_stream_read_handler;
  c->write->handler = ngx_stream_write_handler;
  if (c->read->ready || c->read->eof) {
    ngx_post_event(c->read, &ngx_posted_events);
  } else {
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
      ngx_stream_finalize_session_r(s, "ngx_handle_read_event error");
      return;
    }
  }
  ngx_log_error(NGX_LOG_INFO, c->log, 0, "new session");
  c->log->action = " handle request ";
  
  return;
}


#pragma mark - event handler

static ngx_stream_request_t* ngx_stream_create_request(ngx_stream_session_t*);

static void ngx_stream_read_handler(ngx_event_t *e) {
  ngx_connection_t* c = e->data;
  ngx_stream_session_t* s = c->data;
  ngx_stream_request_t* r = NULL;
  ngx_stream_request_core_srv_conf_t  *pscf;
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  if (e->timedout) {
    ngx_stream_finalize_session_r(s, "ngx_stream_read_handler timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  
  r = ngx_stream_create_request(s);
  if (r == NGX_STREAM_REQUEST_ERROR) {
    ngx_stream_finalize_session_r(s, "ngx_stream_create_request error"
                                  " or connection closed by client");
    return;
  }
  if (r != NULL) {
    if (pscf->proxy_handle_request != NULL) {
      if (pscf->upstream == NULL) {
        if (pscf->init_proxy_handler) {
          pscf->init_proxy_handler(r);
        }
        if (pscf->proxy_handle_request != NULL) {
          pscf->proxy_handle_request(r);
        }
      } else {
        ngx_stream_request_proxy_connect(r);
      }
    } else {
      ngx_stream_request_failed(r, "proxy handler not found");
    }
  } else {
    // 超时时间由具体的parse自行设置
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
      ngx_stream_finalize_session_r(s, "ngx_handle_read_event error");
      return;
    }
    if (!c->read->ready) {
      return;
    }
  }
  // 如果有数据，就需要再次放入事件队列中
  if (c->read->ready) {
    ngx_post_event(c->read, &ngx_posted_events);
  }
}

static void ngx_stream_write_handler(ngx_event_t *e) {
  ngx_connection_t* c = e->data;
  ngx_stream_session_t* s = c->data;
  request_core_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  if (e->timedout) {
    ngx_stream_finalize_session_r(s, "ngx_stream_write_handler timeout");
    return;
  }
  if (e->timer_set) {
    ngx_del_timer(e);
  }
  
  if (ngx_queue_empty(&ctx->wait_send)) {
    return;
  }
  for (ngx_queue_t* q = ngx_queue_head(&ctx->wait_send)
       ; q != ngx_queue_sentinel(&ctx->wait_send)
       ; ) {
    ngx_stream_request_t* r = ngx_queue_data(q, ngx_stream_request_t, list);
    
    /**
     ngx_darwin_sendfile_chain.c 中的ngx_output_chain_to_iovec没有考虑ngx_buf_t size=0
     的情况，会造成writev 卡死的bug
     */
    ngx_regular_request_data(r);
    if (r->data == NULL) {
      // need firstly next, then close request
      q = ngx_queue_next(q);
      // close_request will remove q
      ngx_stream_close_request(r);
      continue;
    }
    
    ngx_chain_t* rc = c->send_chain(c, r->data, 0);
    if (rc == NGX_CHAIN_ERROR) {
      ngx_stream_finalize_session_r(s, "send_chain error");
      return;
    }
    if (rc != NULL) {
      r->data = rc;
      break;
    }

    // need firstly next, then close request
    q = ngx_queue_next(q);
    // close_request will remove q
    ngx_stream_close_request(r);
  }
  
  if (ngx_queue_empty(&ctx->wait_send)) {
    return;
  }
  
  ngx_stream_request_core_srv_conf_t  *pscf;
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_add_timer(e, pscf->send_to_client_timeout);
  if (ngx_handle_write_event(e, 0) != NGX_OK) {
    ngx_stream_finalize_session_r(s, "ngx_handle_write_event error");
    return;
  }
}

#pragma mark - request handler

static ngx_stream_request_t* ngx_stream_create_request(ngx_stream_session_t* s) {
  ngx_stream_request_t* r = NULL;
  ngx_stream_request_core_srv_conf_t  *pscf;
  ngx_stream_upstream_t           *u;
  ngx_stream_upstream_srv_conf_t  *uscf;
  
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  r = pscf->parse_request != NULL? pscf->parse_request(s) : NULL;
  if (r == NULL || r == NGX_STREAM_REQUEST_ERROR) {
    return r;
  }
  
  if (pscf->upstream == NULL) {
    return r;
  }
  
  u = ngx_pcalloc(r->pool, sizeof(ngx_stream_upstream_t));
  if (u == NULL) {
    ngx_stream_request_failed(r, "ngx_pcalloc error");
    return NULL;
  }
  
  u->peer.log = s->connection->log;
  u->peer.log_error = NGX_ERROR_ERR;
  
  u->peer.local = pscf->local;
  u->peer.type = s->connection->type;
  
  uscf = pscf->upstream;
  // 为了兼容session upstream的现有逻辑，在peer.init执行前需要将s->connection->pool换为r->pool
  // peer.init所需要的内存在r->pool 中申请，请参见ngx_stream_upstream_round_robin.c 中
  // ngx_stream_upstream_init_round_robin_peer 的实现
  do {
    s->upstream = u;
    ngx_pool_t* pool = s->connection->pool;
    s->connection->pool = r->pool;
    ngx_int_t rc = uscf->peer.init(s, uscf);
    s->connection->pool = pool;
    if (rc != NGX_OK) {
      ngx_stream_request_failed(r, "peer.init error");
      return NULL;
    }
    r->upstream = s->upstream;
    s->upstream = NULL;
  } while (0);
  
  
  u->peer.start_time = ngx_current_msec;
  
  if (pscf->next_upstream_tries
      && u->peer.tries > pscf->next_upstream_tries)
  {
    u->peer.tries = pscf->next_upstream_tries;
  }
  
  u->proxy_protocol = 0;
  u->start_sec = ngx_time();
  
  return r;
}

static void ngx_stream_close_request(ngx_stream_request_t* r) {
  ngx_stream_session_t* s = r->session;
  request_core_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_queue_remove(&r->list);
  ctx->wait_send_cnt--;
  
  ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "close request %p", r);
  
  for (ngx_stream_request_cleanup_t* cln = r->cln; cln; cln = cln->next) {
    if (cln->handler) {
      cln->handler(cln->data);
      cln->handler = NULL;
    }
  }
  
  ngx_stream_upstream_t* u;
  
  u = r->upstream;
  
  if (u != NULL && u->peer.connection != NULL) {
    ngx_close_connection(u->peer.connection);
  }
  
  ngx_pool_t* pool = r->pool;
  ngx_destroy_pool(pool);
}

extern ngx_stream_request_t* ngx_stream_new_request(ngx_stream_session_t* s) {
  ngx_pool_t* pool = ngx_create_pool(2000, s->connection->log);
  ngx_stream_request_t* r = ngx_pcalloc(pool, sizeof(ngx_stream_request_t));
  r->pool = pool;
  r->session = s;
  r->data = ngx_pcalloc(pool, sizeof(ngx_chain_t));
  r->data->buf = ngx_create_temp_buf(r->pool, 1);
  r->ctx = ngx_pcalloc(pool, sizeof(void**)*ngx_stream_max_module);
  
  request_core_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_queue_insert_tail(&ctx->processing, &r->list);
  ctx->request_cnt++;
  ctx->processing_cnt++;
  
  ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "new request %p", r);
  
  return r;
}

extern void handle_request_done(ngx_stream_request_t* r) {
  ngx_stream_session_t* s = r->session;
  ngx_connection_t* c = s->connection;
  request_core_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_stream_request_core_srv_conf_t  *pscf;
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  
  if (pscf->build_response) {
    pscf->build_response(r);
  }
  
  ngx_queue_remove(&r->list);
  ctx->processing_cnt--;
  ngx_queue_insert_tail(&ctx->wait_send, &r->list);
  ctx->wait_send_cnt++;
  
  ngx_post_event(c->write, &ngx_posted_events);
}

extern void ngx_stream_request_set_header(ngx_stream_request_t *r
                                          , ngx_str_t key, ngx_str_t value) {
  if (r->headers == NULL) {
    r->headers = ngx_pcalloc(r->pool, sizeof(ngx_str_str_rbtree));
    ngx_str_str_rbtree_init(r->headers, r->pool, r->session->connection->log);
  }
  ngx_str_str_rbtree_set_value(r->headers, key, value, 1);
}

extern ngx_str_t ngx_stream_request_get_header(ngx_stream_request_t *r
                                               , ngx_str_t key) {
  ngx_str_t value = ngx_null_string;
  if (r->headers == NULL) {
    return value;
  }
  
  value = ngx_str_str_rbtree_get_value(r->headers, key);
  return value;
}

extern ngx_uint_t ngx_chain_len(ngx_chain_t* chain) {
  ngx_uint_t len = 0;
  for (; chain != NULL; chain = chain->next) {
    len += chain->buf->last - chain->buf->pos;
  }
  return len;
}

extern void ngx_stream_finalize_session_r(ngx_stream_session_t *s, char* reason) {
  ngx_log_t* log = s->connection->log;
  log->action = NULL;
  
  ngx_log_error(NGX_LOG_ERR, log, 0, "finalize session because %s", reason);
  
  request_core_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  for (ngx_queue_t* q = ngx_queue_head(&ctx->processing)
       ; q != ngx_queue_sentinel(&ctx->processing)
       ; ) {
    ngx_queue_t* qtmp = q;
    q = ngx_queue_next(q);
    ngx_stream_close_request(ngx_queue_data(qtmp, ngx_stream_request_t, list));
  }
  for (ngx_queue_t* q = ngx_queue_head(&ctx->wait_send)
       ; q != ngx_queue_sentinel(&ctx->wait_send)
       ; ) {
    ngx_queue_t* qtmp = q;
    q = ngx_queue_next(q);
    ngx_stream_close_request(ngx_queue_data(qtmp, ngx_stream_request_t, list));
  }
  
  for (ngx_stream_cleanup_t * cln = ctx->cleanups; cln; cln = cln->next) {
    if (cln->handler) {
      cln->handler(cln->data);
      cln->handler = NULL;
    }
  }
  
  ngx_stream_close_connection(s->connection);
}

extern void ngx_regular_buf(ngx_buf_t* buf) {
  off_t size = ngx_buf_size(buf);
  if (size != 0) {
    ngx_memmove(buf->start, buf->pos, size);
  }
  buf->pos = buf->start;
  buf->last = buf->pos + size;
}

extern ngx_stream_cleanup_t * ngx_stream_cleanup_add(ngx_stream_session_t *s) {
  request_core_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_stream_cleanup_t  *cln;
  cln = ngx_palloc(s->connection->pool, sizeof(ngx_stream_cleanup_t));
  if (cln == NULL) {
    return NULL;
  }
  
  cln->data = NULL;
  cln->handler = NULL;
  cln->next = ctx->cleanups;
  
  ctx->cleanups = cln;
  
  return cln;
}

extern
ngx_stream_request_cleanup_t * ngx_stream_request_cleanup_add(ngx_stream_request_t* r){
  ngx_stream_request_cleanup_t  *cln;
  cln = ngx_palloc(r->pool, sizeof(ngx_stream_request_cleanup_t));
  if (cln == NULL) {
    return NULL;
  }
  
  cln->data = NULL;
  cln->handler = NULL;
  cln->next = r->cln;
  
  r->cln = cln;
  
  return cln;
}

extern void ngx_regular_request_data(ngx_stream_request_t* r) {
  if (r->data == NULL) {
    return;
  }
  for (ngx_chain_t* chain = r->data->next, *prev = r->data
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

