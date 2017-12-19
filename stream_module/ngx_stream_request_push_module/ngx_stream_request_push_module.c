//
//  ngx_stream_request_push_module.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/10/25.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>

#include <ngx_channel.h>

#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_request_push_module

#ifdef core_module
#undef core_module
#endif
#define core_module ngx_stream_request_core_module

typedef struct ngx_stream_push_msg_s ngx_stream_push_msg_t;

typedef struct{
  uint32_t hostname; // 4 byte
  u_short slot; // 2 byte 总slot不能超过65535。NGX_MAX_PROCESSES 设置很重要
  u_short pid; // 2 byte  只是存储低两位，便于快速对比
  //  uint64_t session_tsoken; // 4 byte time + 4 byte sequece
  uint32_t time_stamp; // 4 byte  unit: s
  uint32_t session_sequece; // 4 byte
} ngx_stream_request_push_token_t;

struct ngx_stream_push_msg_s {
  struct {
    uint32_t time_stamp;
    uint32_t session_sequece;
  } session_token;
  
  ngx_stream_push_msg_t* next;
  
  ngx_uint_t data_len;
  u_char data[0];
};


#define NGX_STREAM_PUSH_CHANNEL_CMD_REQUEST   0
#define NGX_STREAM_PUSH_CHANNEL_CMD_RESPONSE  1

typedef struct{
  uint16_t sequece;
  ngx_int_t src_slot;
  ngx_uint_t command;
  union {
    struct {
      uint32_t time_stamp;
      uint32_t session_sequece;
    } session_token;
    u_char  success;
  } data;
} ngx_stream_push_channel_t;

typedef struct{
  //  ngx_shm_zone_t    *shm_zone;
  
  size_t                    share_memory_size;
  // share memory
  ngx_slab_pool_t*          shpool;
  ngx_shmtx_sh_t*           work_locks;
  ngx_shmtx_t*              work_mutexes;
  ngx_stream_push_msg_t**   messages;
  ngx_pid_t*                old_pids;
  
  // process memory
  ngx_socket_t              socketpairs[NGX_MAX_PROCESSES][2];
  uint16_t                  channel_sequece;
  uint32_t                  session_sequece;
  ngx_radix_tree_t*         sessions;
  ngx_pool_t*               pool;
  uint32_t                  hostname;
  ngx_radix_tree_t*         channel_requests;
  
} ngx_stream_request_push_main_conf_t;

typedef struct{
  ngx_msec_t recv_timeout;
} ngx_stream_request_push_svr_conf_t;

static ngx_int_t preconfiguration(ngx_conf_t *cf);
static void *ngx_stream_request_push_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_request_push_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_stream_request_push_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_request_push_merge_srv_conf(ngx_conf_t *cf
                                                  , void *parent, void *child);

static ngx_int_t  push_init_module(ngx_cycle_t *cycle);
static ngx_int_t  push_init_process(ngx_cycle_t *cycle);
static void       push_exit_process(ngx_cycle_t *cycle);

static char *push_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t
ngx_stream_push_create_shmtx(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, char *name);
static ngx_int_t ngx_stream_push_ipc_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_stream_push_ipc_init_process(ngx_cycle_t *cycle);

static void push_initializer(ngx_stream_session_t*);
static void push_cleanup(void *data);

static ngx_stream_session_t* find_session(ngx_radix_tree_t* sessions
                                          , uint32_t time_stamp
                                          , uint32_t session_sequece);
static void push_msg_to_client(void);

static void push_request_cleanup_handler(void* data);

static void push_channel_event_handler_pt(ngx_event_t *ev);
static ngx_int_t ngx_stream_push_write_channel(ngx_socket_t s
                                               , ngx_stream_push_channel_t *ch
                                               , size_t size
                                               , ngx_log_t *log);
static ngx_int_t ngx_stream_push_read_channel(ngx_socket_t s
                                              , ngx_stream_push_channel_t *ch
                                              , size_t size
                                              , ngx_log_t *log);
static void ngx_stream_request_push_token_to_str(ngx_stream_request_push_token_t
                                                 , ngx_str_t*);
static ngx_stream_request_push_token_t ngx_stream_request_push_str_to_token(ngx_str_t);

static ngx_int_t
ngx_stream_request_push_get_session_token(ngx_stream_session_t *s,
                                         ngx_stream_variable_value_t *v
                                         , uintptr_t data);

static ngx_stream_variable_t  ngx_stream_push_variables[] = {
  { ngx_string("session-token"), NULL
    , ngx_stream_request_push_get_session_token,
    0, 0, 0 },
  
  { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_command_t  ngx_stream_push_commands[] = {
  
  { ngx_string("push_protocol"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    push_conf,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  { ngx_string("push_receive_timeout"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
    ngx_conf_set_msec_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(ngx_stream_request_push_svr_conf_t, recv_timeout),
    NULL },
  
  { ngx_string("push_shared_memory_size"),
    NGX_STREAM_MAIN_CONF|NGX_CONF_NOARGS,
    ngx_conf_set_size_slot,
    NGX_STREAM_MAIN_CONF_OFFSET,
    offsetof(ngx_stream_request_push_main_conf_t, share_memory_size),
    NULL },
  
  ngx_null_command
};

static ngx_stream_module_t  ngx_stream_push_module_ctx = {
  preconfiguration,
  NULL,            /* postconfiguration */
  
  ngx_stream_request_push_create_main_conf,  /* create main configuration */
  ngx_stream_request_push_init_main_conf,    /* init main configuration */
  
  ngx_stream_request_push_create_srv_conf,   /* create server configuration */
  ngx_stream_request_push_merge_srv_conf     /* merge server configuration */
};

ngx_module_t  ngx_stream_request_push_module = {
  NGX_MODULE_V1,
  &ngx_stream_push_module_ctx,           /* module context */
  ngx_stream_push_commands,              /* module directives */
  NGX_STREAM_MODULE,                     /* module type */
  NULL,                                  /* init master */
  push_init_module,                      /* init module */
  push_init_process,                     /* init process */
  NULL,                                  /* init thread */
  NULL,                                  /* exit thread */
  push_exit_process,                     /* exit process */
  NULL,                                  /* exit master */
  NGX_MODULE_V1_PADDING
};

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - conf
#endif

static ngx_int_t
ngx_stream_push_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);

static ngx_str_t  ngx_stream_push_shm_name = ngx_string("stream_request_push_stream_module");
static void *ngx_stream_request_push_create_main_conf(ngx_conf_t *cf) {
  ngx_stream_request_push_main_conf_t* pmcf;
  
  pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_request_push_main_conf_t));
  
  pmcf->share_memory_size = NGX_CONF_UNSET_SIZE;
  
  int i = 0;
  for (i = 0; i < NGX_MAX_PROCESSES; ++i) {
    pmcf->socketpairs[i][0] = -1;
    pmcf->socketpairs[i][1] = -1;
  }
  
  return pmcf;
}

static ngx_int_t preconfiguration(ngx_conf_t *cf) {
  ngx_stream_variable_t  *var, *v;
  
  for (v = ngx_stream_push_variables; v->name.len; v++) {
    var = ngx_stream_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      return NGX_ERROR;
    }
    
    var->get_handler = v->get_handler;
    var->data = v->data;
  }
  
  return NGX_OK;
}

static char *ngx_stream_request_push_init_main_conf(ngx_conf_t *cf, void *conf) {
  ngx_stream_request_push_main_conf_t* pmcf = conf;
  size_t                               shm_size;
  
  pmcf->hostname = (uint32_t)ngx_hash_key(cf->cycle->hostname.data
                                          , cf->cycle->hostname.len);
  
  if (pmcf->share_memory_size == NGX_CONF_UNSET_SIZE) {
    pmcf->share_memory_size = 0;
  }
  shm_size = ngx_max(pmcf->share_memory_size, 32 * ngx_pagesize);
  shm_size = ngx_align(shm_size, ngx_pagesize);
  
  ngx_shm_zone_t* zone = ngx_shared_memory_add(cf, &ngx_stream_push_shm_name
                                               , shm_size
                                               , &ngx_stream_request_push_module);
  if (zone == NULL) {
    return NGX_CONF_ERROR;
  }
  
  zone->init = ngx_stream_push_init_shm_zone;
  zone->data = pmcf;
  
  return NGX_CONF_OK;
}

static void *ngx_stream_request_push_create_srv_conf(ngx_conf_t *cf) {
  ngx_stream_request_push_svr_conf_t* pscf;
  pscf = ngx_palloc(cf->pool, sizeof(ngx_stream_request_push_svr_conf_t));
  pscf->recv_timeout = NGX_CONF_UNSET_MSEC;
  
  return pscf;
}

static char *ngx_stream_request_push_merge_srv_conf(ngx_conf_t *cf
                                                    , void *parent, void *child) {
  ngx_stream_request_push_svr_conf_t* conf = child;
  ngx_stream_request_push_svr_conf_t* prev = parent;

  ngx_conf_merge_msec_value(conf->recv_timeout, prev->recv_timeout, 60000);
  
  return NGX_CONF_OK;
}

static ngx_int_t
ngx_stream_push_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {
  ngx_stream_request_push_main_conf_t* pmcf = shm_zone->data;
  
  pmcf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
  
  return NGX_OK;
}

#define WORK_INDEX_STR(index) "wroker"#index

static ngx_int_t  push_init_module(ngx_cycle_t *cycle) {
//  ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx
//                                                          , ngx_core_module);
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(cycle, this_module);
  
//  ngx_int_t workers = ccf->worker_processes;
  ngx_int_t workers = NGX_MAX_PROCESSES;
  
  ngx_shmtx_lock(&pmcf->shpool->mutex);
  pmcf->work_mutexes = ngx_slab_calloc_locked(pmcf->shpool
                                          , workers*sizeof(ngx_shmtx_t));
  pmcf->work_locks = ngx_slab_calloc_locked(pmcf->shpool
                                        , workers*sizeof(ngx_shmtx_sh_t));
  pmcf->messages = ngx_slab_calloc_locked(pmcf->shpool
                                          , workers*sizeof(ngx_stream_push_msg_t*));
  pmcf->old_pids = ngx_slab_calloc_locked(pmcf->shpool, workers*sizeof(ngx_pid_t));
  int i = 0;
  for (i = 0; i < workers; ++i) {
    ngx_stream_push_create_shmtx(&pmcf->work_mutexes[i]
                                 , &pmcf->work_locks[i], WORK_INDEX_STR(i));
    pmcf->old_pids[i] = -1;
  }
  ngx_shmtx_unlock(&pmcf->shpool->mutex);
  
  return ngx_stream_push_ipc_init_module(cycle);

}

#define SESSION_RADIX_MASK 0xffffffff

static  void       push_clean_process(ngx_cycle_t *cycle) {
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(cycle, this_module);
  ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx
                                                          , ngx_core_module);
  ngx_int_t workers = ccf->worker_processes;
  
  ngx_pid_t old_pid = pmcf->old_pids[ngx_process_slot];
  if (old_pid != -1) {
    // force unlock mutex locked by old_pid
    ngx_shmtx_force_unlock(&pmcf->shpool->mutex, old_pid);
    int i = 0;
    for (i = 0; i < workers; ++i) {
      ngx_shmtx_force_unlock(&pmcf->work_mutexes[i], old_pid);
    }
  }
  pmcf->old_pids[ngx_process_slot] = ngx_pid;
  
  // free old share memory
  ngx_stream_push_msg_t* old_messages = NULL;
  ngx_shmtx_lock(&pmcf->work_mutexes[ngx_process_slot]);
  old_messages = pmcf->messages[ngx_process_slot];
  pmcf->messages[ngx_process_slot] = NULL;
  ngx_shmtx_unlock(&pmcf->work_mutexes[ngx_process_slot]);
  
  if (old_messages != NULL) {
    ngx_shmtx_lock(&pmcf->shpool->mutex);
    while (old_messages != NULL) {
      ngx_stream_push_msg_t* p = old_messages;
      old_messages = old_messages->next;
      ngx_slab_free_locked(pmcf->shpool, p);
    }
    ngx_shmtx_unlock(&pmcf->shpool->mutex);
  }
}

static ngx_int_t  push_init_process(ngx_cycle_t *cycle) {
  
  ngx_debug_point();
  
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(cycle, this_module);
  
  pmcf->channel_sequece = 0;
  pmcf->session_sequece = 0;
  pmcf->pool = cycle->pool;

  pmcf->sessions = ngx_radix_tree_create(pmcf->pool, -1);
  pmcf->channel_requests = ngx_radix_tree_create(pmcf->pool, -1);
  
  // 原框架没有设置ngx_processes数组中当前进程的pid
  ngx_processes[ngx_process_slot].pid = ngx_pid;
  
  ngx_int_t rc = ngx_stream_push_ipc_init_process(cycle);
  
  // 分析 ngx_reap_children 可以得出：如果是crash 引起的进程重启，会在原来的ngx_process_slot重新
  //  生成新的进程，执行push_clean_process打扫之前遗留的战场
  push_clean_process(cycle);
  
  return rc;
}

static void       push_exit_process(ngx_cycle_t *cycle) {
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(cycle, this_module);

  push_clean_process(cycle);
  
  ngx_close_channel(&pmcf->socketpairs[ngx_process_slot][1], cycle->log);
  
}

static void init_parse_request(ngx_stream_session_t* s);
static ngx_stream_request_t* get_request(ngx_stream_session_t* s);
static ngx_int_t handle_request(ngx_stream_request_t* r);
static ngx_int_t build_response(ngx_stream_request_t* r);

static char *push_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_request_core_srv_conf_t* cscf;
  cscf = ngx_stream_conf_get_module_srv_conf(cf, core_module);
  
  cscf->protocol.init_parser = init_parse_request;
  cscf->protocol.get_request = get_request;
  cscf->protocol.handler.name = "push";
  cscf->protocol.handler.handle_request = handle_request;
  cscf->protocol.handler.build_response = build_response;
  cscf->protocol.handler.index = 0;
  
  return NGX_CONF_OK;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - logic protocol
#endif

typedef struct{
  uint32_t time_stamp;
  uint32_t session_seq;
} request_session_ctx_t;

static void push_cleanup(void *data) {
  ngx_stream_session_t* s = data;
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_get_module_main_conf(s, this_module);
  request_session_ctx_t* r_ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_radix_tree_t* second = (ngx_radix_tree_t*)ngx_radix32tree_find(
                                      pmcf->sessions, r_ctx->time_stamp);
  if (second == (ngx_radix_tree_t*)NGX_RADIX_NO_VALUE) {
    return;
  }
  ngx_radix32tree_delete(second, r_ctx->session_seq, SESSION_RADIX_MASK);
}

/**
 *
 * request:
 *  sequece | token | len | data
 *    sizeof(sequece) = 4. net order
 *    sizeof(token) = 32 . hex
 *    sizeof(len) = 4. len = sizof(data) net order
 *
 * response:
 *  sequece | state
 *    sizeof(sequece) = 4. net order
 *    sizeof(state) = 1. --- 0: success; 1: hostname error; 2: token not exist
 *
 */

/*  return ngx_stream_request_t*: 解析到一个request
 return REQUEST_AGAIN: 解析数据不够
 return REQUEST_DONE: 进行下一步
 */
#define REQUEST_AGAIN (ngx_stream_request_t*) NGX_AGAIN
#define REQUEST_DONE (ngx_stream_request_t*) NGX_DONE
typedef ngx_stream_request_t* (*request_handler_t)(ngx_stream_session_t*);

typedef struct{
  ngx_stream_request_t* r;
  request_handler_t handler;
  u_char head[40];
  ssize_t last;
} push_session_ctx_t;

typedef struct{
  uint32_t sequece;
  ngx_stream_request_push_token_t token;
  ngx_stream_push_msg_t* msg;
  ngx_int_t done;
} push_request_ctx_t;

static ngx_stream_request_t* request_parse_header(ngx_stream_session_t* s);
static ngx_stream_request_t* request_parse_data(ngx_stream_session_t*);

static void init_parse_request(ngx_stream_session_t* s){
  push_session_ctx_t* ctx = ngx_pcalloc(s->connection->pool, sizeof(push_session_ctx_t));
  ctx->handler = request_parse_header;
  ngx_stream_set_ctx(s, ctx, this_module);
}

static ngx_stream_request_t* get_request(ngx_stream_session_t* s) {
  push_session_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  
  ngx_stream_request_t* r = NULL;
  do {
    r = ctx->handler(s);
  } while (r == REQUEST_DONE);
  if (r == REQUEST_AGAIN) {
    return NGX_STREAM_REQUEST_AGAIN;
  }
  if (r == NGX_STREAM_REQUEST_ERROR) {
    return NGX_STREAM_REQUEST_ERROR;
  }

  return r;
}

static ngx_int_t build_response(ngx_stream_request_t* r) {
  push_request_ctx_t* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  
  ngx_chain_t* ch = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  ch->buf = ngx_create_temp_buf(r->pool, 4);
  *((uint32_t*)ch->buf->last) = htonl(r_ctx->sequece);
  ch->buf->last += 4;
  
  ch->next = r->data;
  r->data = ch;
  
  return NGX_OK;
}

static void create_failed_request(ngx_stream_request_t* r, u_char st) {
  r->data = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
  r->data->buf = ngx_create_temp_buf(r->pool, 1);
  *r->data->buf->last = st;
  r->data->buf->last += 1;
  
  r->error = 1;
}

static ngx_int_t handle_request(ngx_stream_request_t* r) {
  ngx_stream_session_t* s = r->session;
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_get_module_main_conf(s, this_module);
  push_request_ctx_t* r_ctx = ngx_stream_request_get_module_ctx(r, this_module);
  ngx_log_t* log = s->connection->log;
  
  if (r_ctx->done) { // 已经异步处理结束
    return NGX_HANDLER_STOP;
  }
  
  ngx_log_debug8(NGX_LOG_DEBUG_STREAM, log, 0, "handle push request, r:%p, seq:%uD. "
                 "h:%uD, pid&0xffff:%P, slot:%ud. current---h:%uD, pid&0xffff:%P, slot:%ud"
                 , r, r_ctx->sequece
                 , r_ctx->token.hostname, r_ctx->token.pid&0xffff
                 , r_ctx->token.slot
                 , pmcf->hostname, ngx_pid&0xffff, ngx_process_slot);
  
  ngx_int_t error = 0;
  
  if (r_ctx->token.hostname != pmcf->hostname) {
    ngx_log_error(NGX_LOG_ERR, log
                  , 0, "r(%p) hostname(%uD) != local hostname(%uD)"
                  , r, r_ctx->token.hostname, pmcf->hostname);
    error = 1;
  }
  // token 异常
  if (r_ctx->token.pid != (ngx_processes[r_ctx->token.slot].pid&0xffff)) {
    ngx_log_error(NGX_LOG_ERR, log, 0
                  , "r(%p) token.pid&0xffff(%P) != token.slot->pid&0xffff(%P)"
                  , r, r_ctx->token.pid&0xffff
                  , ngx_processes[r_ctx->token.slot].pid&0xffff);
    error = 2;
    
    // free share memory of the r_ctx->token.slot
    ngx_stream_push_msg_t* msg = NULL;
    ngx_shmtx_lock(&pmcf->work_mutexes[r_ctx->token.slot]);
    msg = pmcf->messages[r_ctx->token.slot];
    pmcf->messages[r_ctx->token.slot] = NULL;
    ngx_shmtx_unlock(&pmcf->work_mutexes[r_ctx->token.slot]);
    
    while (msg != NULL) {
      ngx_stream_push_msg_t* p = msg;
      msg = msg->next;
      ngx_slab_free(pmcf->shpool, p);
    }
  }
  
  if (error != 0) {
    create_failed_request(r, error);
    return NGX_ERROR;
  }
  
  ngx_int_t rc = NGX_HANDLER_STOP;
  if (r_ctx->token.slot == ngx_process_slot) {
    if (find_session(pmcf->sessions, r_ctx->token.time_stamp
                     , r_ctx->token.session_sequece)) {
      create_failed_request(r, 0);
    } else {
      ngx_log_error(NGX_LOG_ERR, log, 0, "push r(%p) not find session", r);
      create_failed_request(r, 2);
      rc = NGX_ERROR;
    }
    
    push_msg_to_client();
    return rc;
  }
  
  ngx_stream_push_channel_t ch;
  ch.command = NGX_STREAM_PUSH_CHANNEL_CMD_REQUEST;
  ch.src_slot = ngx_process_slot;
  ch.data.session_token.session_sequece = r_ctx->token.session_sequece;
  ch.data.session_token.time_stamp = r_ctx->token.time_stamp;
  ch.sequece = ++pmcf->channel_sequece;
  
  ngx_radix32tree_insert(pmcf->channel_requests, ch.sequece<<16
                         , 0xffff0000, (uintptr_t)r);
  
  ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0
                 , "notify other pid, r=%p, request_seq=%ud"
                 , r, ch.sequece);
  
  ngx_stream_push_write_channel(pmcf->socketpairs[r_ctx->token.slot][0]
                                , &ch, sizeof(ngx_stream_push_channel_t)
                                , s->connection->log);
  
  return NGX_AGAIN;
}

static ngx_stream_request_t* request_parse_header(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_push_svr_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  push_session_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_get_module_main_conf(s, this_module);
  
  ssize_t n = c->recv(c, ctx->head+ctx->last, 40-ctx->last);
  if (n <= 0 && n != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (n == NGX_AGAIN) {
    ngx_add_timer(c->read, pscf->recv_timeout);
    return REQUEST_AGAIN;
  }
  ctx->last += n;
  if (ctx->last < 40) {
    ngx_add_timer(c->read, pscf->recv_timeout);
    return REQUEST_AGAIN;
  }
  
  ctx->last = 0;
  ctx->handler = request_parse_data;
  ctx->r = ngx_stream_new_request(s);
  
  // head
  push_request_ctx_t* r_ctx = ngx_pcalloc(ctx->r->pool, sizeof(push_request_ctx_t));
  ngx_stream_request_set_ctx(ctx->r, r_ctx, this_module);
  r_ctx->sequece = ntohl(*(uint32_t*)ctx->head);
  ngx_str_t token = {32, ctx->head+4};
  ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "push token is %V", &token);
  r_ctx->token = ngx_stream_request_push_str_to_token(token);
  uint32_t datalen = ntohl(*(uint32_t*)(ctx->head+36));
  
  // data
  ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx
                                                          , ngx_core_module);
  ngx_int_t workers = ccf->worker_processes;
  if (r_ctx->token.slot >= workers
      || r_ctx->token.hostname != pmcf->hostname) {
    // 数据丢弃，真正处理的数据是放在共享内存中
    ctx->r->data = ngx_pcalloc(ctx->r->pool, sizeof(ngx_chain_t));
    ctx->r->data->buf = ngx_create_temp_buf(ctx->r->pool, datalen);
  } else {
    ngx_stream_request_push_main_conf_t* pmcf;
    pmcf = ngx_stream_get_module_main_conf(s, this_module);
    r_ctx->msg = ngx_slab_calloc(pmcf->shpool, sizeof(ngx_stream_push_msg_t)+datalen);
    r_ctx->msg->data_len = datalen;
    r_ctx->msg->session_token.session_sequece = r_ctx->token.session_sequece;
    r_ctx->msg->session_token.time_stamp = r_ctx->token.time_stamp;
    
    ngx_shmtx_lock(&pmcf->work_mutexes[r_ctx->token.slot]);
    r_ctx->msg->next = pmcf->messages[r_ctx->token.slot];
    pmcf->messages[r_ctx->token.slot] = r_ctx->msg;
    ngx_shmtx_unlock(&pmcf->work_mutexes[r_ctx->token.slot]);
    
    ctx->r->data = ngx_pcalloc(ctx->r->pool, sizeof(ngx_chain_t));
    ctx->r->data->buf = ngx_create_temp_buf(ctx->r->pool, 1);
    ctx->r->data->buf->start = r_ctx->msg->data;
    ctx->r->data->buf->pos = ctx->r->data->buf->start;
    ctx->r->data->buf->last = ctx->r->data->buf->pos;
    ctx->r->data->buf->end = r_ctx->msg->data + r_ctx->msg->data_len;
  }
  
  return REQUEST_DONE;
}

static ngx_stream_request_t* request_parse_data(ngx_stream_session_t* s) {
  ngx_connection_t* c = s->connection;
  ngx_stream_request_push_svr_conf_t* pscf = ngx_stream_get_module_srv_conf(s, this_module);
  push_session_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  ngx_stream_request_t* r = ctx->r;
  
  ssize_t n = c->recv(c, r->data->buf->last, r->data->buf->end - r->data->buf->last);
  if (n <= 0 && n != NGX_AGAIN) {
    return NGX_STREAM_REQUEST_ERROR;
  }
  if (n == NGX_AGAIN) {
    ngx_add_timer(c->read, pscf->recv_timeout);
    return REQUEST_AGAIN;
  }
  r->data->buf->last += n;
  if (r->data->buf->end != r->data->buf->last) {
    ngx_add_timer(c->read, pscf->recv_timeout);
    return REQUEST_AGAIN;
  }
  
  ctx->handler = request_parse_header;
  ctx->r = NULL;
  
  return r;
}

static void push_channel_event_handler_pt(ngx_event_t *ev) {
  ngx_int_t          n;
  ngx_stream_push_channel_t      ch;
  ngx_connection_t  *c;
  
  // os/unix/ngx_channel.c 
  
//  if (ev->timedout) {
//    ev->timedout = 0;
//    return;
//  }
  
  // log in error.log
  
  c = ev->data;
  
  ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ev->log, 0, "push channel handler");
  
  for ( ;; ) {
    
    n = ngx_stream_push_read_channel(c->fd, &ch, sizeof(ngx_stream_push_channel_t)
                                     , ev->log);
    
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ev->log, 0, "channel read result: %i", n);
    
    if (n == NGX_ERROR) {
      
      if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
        ngx_del_conn(c, 0);
      }
      
      ngx_close_connection(c);
      return;
    }
    
    if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
      if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
        return;
      }
    }
    
    if (n == NGX_AGAIN) {
      return;
    }
    
    ngx_log_debug5(NGX_LOG_DEBUG_STREAM, ev->log, 0,
                   "push channel command. cmd:%ui, ch_seq:%ud, src_slot:%i"
                   ", time:%uD, session_seq:%uD"
                   , ch.command
                   , ch.sequece, ch.src_slot
                   , ch.data.session_token.time_stamp
                   , ch.data.session_token.session_sequece);
    
    ngx_stream_request_push_main_conf_t* pmcf;
    pmcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle, this_module);
    
    switch (ch.command) {
        
      case NGX_STREAM_PUSH_CHANNEL_CMD_REQUEST:
        
        ch.command = NGX_STREAM_PUSH_CHANNEL_CMD_RESPONSE;
        if (find_session(pmcf->sessions, ch.data.session_token.time_stamp
                         , ch.data.session_token.session_sequece)) {
          ch.data.success = 1;
        } else {
          ngx_log_error(NGX_LOG_ERR, ev->log, 0
                        , "ch_seq(%ud) of src_slot(%i) not find in current_pid(%P)"
                        , ch.sequece, ch.src_slot, ngx_pid);
          ch.data.success = 0;
        }
        ngx_stream_push_write_channel(pmcf->socketpairs[ch.src_slot][0]
                                      , &ch, sizeof(ngx_stream_push_channel_t)
                                      , ev->log);
        
        push_msg_to_client();
        
        break;
        
      case NGX_STREAM_PUSH_CHANNEL_CMD_RESPONSE:
        {
          uintptr_t r = ngx_radix32tree_find(pmcf->channel_requests, ch.sequece<<16);
          if (r == NGX_RADIX_NO_VALUE) {
            ngx_log_error(NGX_LOG_ERR, ev->log, 0
                          , "seq(%ud) not find request in channel_requests"
                          , ch.sequece);
            return;
          }
          u_char st = ch.data.success == 1? 0 : 2;
          ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ev->log, 0
                         , "req(%p) push state is %ud", r, st);
          create_failed_request((ngx_stream_request_t*)r, st);
          push_request_ctx_t* r_ctx =
          ngx_stream_request_get_module_ctx((ngx_stream_request_t*)r
                                            , this_module);
          r_ctx->done = 1; // 异步处理请求结束
          ngx_stream_handle_request((ngx_stream_request_t*)r);
        }
        break;
    }
  }
}

static ngx_int_t
ngx_stream_request_push_get_session_token(ngx_stream_session_t *s,
                                          ngx_stream_variable_value_t *v
                                          , uintptr_t data) {
  ngx_stream_request_push_svr_conf_t* pscf;
  pscf = ngx_stream_get_module_srv_conf(s, this_module);
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_get_module_main_conf(s, this_module);
  
  ngx_stream_cleanup_t* cln = ngx_stream_cleanup_add(s);
  cln->handler = push_cleanup;
  cln->data = s;
  
  request_session_ctx_t* r_ctx = ngx_palloc(s->connection->pool
                                            , sizeof(request_session_ctx_t));
  r_ctx->time_stamp = (uint32_t) ngx_time();
  
  
  r_ctx->session_seq = (uint32_t)(++pmcf->session_sequece);
  ngx_stream_set_ctx(s, r_ctx, this_module);
  
  ngx_radix_tree_t* second = (ngx_radix_tree_t*)NGX_RADIX_NO_VALUE;
  if ((second = (ngx_radix_tree_t*)ngx_radix32tree_find(pmcf->sessions, r_ctx->time_stamp))
      ==  (ngx_radix_tree_t*)NGX_RADIX_NO_VALUE) {
    second = ngx_radix_tree_create(pmcf->pool, -1);
    ngx_radix32tree_insert(pmcf->sessions, r_ctx->time_stamp
                           , SESSION_RADIX_MASK, (uintptr_t)second);
  }
  ngx_radix32tree_insert(second, r_ctx->session_seq
                         , SESSION_RADIX_MASK, (uintptr_t)s);
  
  ngx_stream_request_push_token_t token = {
    pmcf->hostname, ngx_process_slot, ngx_pid
    , r_ctx->time_stamp, r_ctx->session_seq
  };
  ngx_str_t token_str;
  token_str.data = ngx_pcalloc(s->connection->pool
                               , 2*sizeof(ngx_stream_request_push_token_t));
  token_str.len = 0;
  ngx_stream_request_push_token_to_str(token, &token_str);
  
  v->data = token_str.data;
  v->len = (unsigned)token_str.len;
  v->not_found = 0;
  v->valid = 1;
  v->no_cacheable = 0;
  
  return NGX_OK;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - util
#endif

static ngx_int_t
ngx_stream_push_create_shmtx(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, char *name) {
  u_char           *file;
  
#if (NGX_HAVE_ATOMIC_OPS)
  
  file = NULL;
  
#else
  
  ngx_str_t        logs_dir = ngx_string("logs/");
  
  if (ngx_conf_full_name((ngx_cycle_t  *) ngx_cycle, &logs_dir, 0) != NGX_OK) {
    return NGX_ERROR;
  }
  
  file = ngx_pnalloc(ngx_cycle->pool, logs_dir.len + ngx_strlen(name));
  if (file == NULL) {
    return NGX_ERROR;
  }
  
  (void) ngx_sprintf(file, "%V%s%Z", &logs_dir, name);
  
#endif
  
  if (ngx_shmtx_create(mtx, addr, file) != NGX_OK) {
    return NGX_ERROR;
  }
  
  return NGX_OK;
}

static ngx_stream_session_t* find_session(ngx_radix_tree_t* sessions
                                          , uint32_t time_stamp
                                          , uint32_t session_sequece) {
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle, this_module);
  
  uintptr_t second = ngx_radix32tree_find(pmcf->sessions, time_stamp);
  if (second == NGX_RADIX_NO_VALUE) {
    return NULL;
  }
  uintptr_t session = ngx_radix32tree_find((ngx_radix_tree_t*)second
                                           , session_sequece);
  if (session == NGX_RADIX_NO_VALUE) {
    return NULL;
  }
  
  return (ngx_stream_session_t*)session;
}

static void push_msg_to_client() {
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle, this_module);
  ngx_stream_push_msg_t* msgs = NULL;
  
  ngx_shmtx_lock(&pmcf->work_mutexes[ngx_process_slot]);
  msgs = pmcf->messages[ngx_process_slot];
  pmcf->messages[ngx_process_slot] = NULL;
  ngx_shmtx_unlock(&pmcf->work_mutexes[ngx_process_slot]);
  
  while (msgs != NULL) {
    ngx_stream_push_msg_t* p =msgs;
    msgs = msgs->next;
    ngx_stream_session_t* s = find_session(pmcf->sessions
                                           , p->session_token.time_stamp
                                           , p->session_token.session_sequece);
    
    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0
                   , "push_msg_to_client time(%uD)&session_seq(%uD)"
                   " find session(%p) in pid(%P)"
                   , p->session_token.time_stamp
                   , p->session_token.session_sequece
                   , s, ngx_pid);
    
    if (s == NULL) {
      ngx_slab_free(pmcf->shpool, p);
    } else {
      ngx_stream_request_t* r = ngx_stream_new_request(s);
      ngx_stream_request_cleanup_t* cln = ngx_stream_request_cleanup_add(r);
      cln->handler = push_request_cleanup_handler;
      cln->data = p;
      r->data = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
      r->data->buf = ngx_create_temp_buf(r->pool, 1);
      r->data->buf->start = p->data;
      r->data->buf->end = p->data + p->data_len;
      r->data->buf->pos = r->data->buf->start;
      r->data->buf->last = r->data->buf->end;
      ngx_stream_handle_request_from(r, -1, 1);
    }
  }
}

static void push_request_cleanup_handler(void* data) {
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle, this_module);
  
  ngx_slab_free(pmcf->shpool, data);
}

/**
 * 改写 ngx_string.c 中的ngx_hextoi(...)
 * 统一规定 hex的低位对应内存中的低位
 * 由于都使用net order, 所以 hex低位实际对应数字逻辑高位
 */
static uint8_t hextoi(u_char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else {
    c = (u_char) (c | 0x20);
    return c - 'a' + 10;
  }
}
static ngx_int_t
ngx_hextoi_1(u_char *line, size_t n) {
  // n % 2 == 0
  uint8_t da[n/2];
  size_t i = 0;
  for (i = 0; i < n; i+=2) {
    da[i/2] = (hextoi(line[i]) << 4) + hextoi(line[i+1]);
  }
  
  switch (n) {
    case 2:
      return *(uint8_t*)da;
    
    case 4:
      return *(uint16_t*)da;
      
    case 8:
      return *(uint32_t*)da;
      
    case 16:
      return *(uint64_t*)da;
      
    default:
      return 0;
  }
  
}

static void ngx_stream_request_push_token_to_str(ngx_stream_request_push_token_t token
                                                 , ngx_str_t* str) {
  token.hostname = htonl(token.hostname);
  token.pid = htons(token.pid);
  token.session_sequece = htonl(token.session_sequece);
  token.slot = htons(token.slot);
  token.time_stamp = htonl(token.time_stamp);
  
  ngx_hex_dump(str->data, (u_char*)&token, sizeof(token));
  str->len = 2*sizeof(ngx_stream_request_push_token_t);
}

static ngx_stream_request_push_token_t ngx_stream_request_push_str_to_token(ngx_str_t str) {
  ngx_stream_request_push_token_t token;
  ngx_memzero(&token, sizeof(ngx_stream_request_push_token_t));
  
  if (str.len != 2*sizeof(ngx_stream_request_push_token_t)) {
    return token;
  }
  
  token.hostname = ntohl((uint32_t)ngx_hextoi_1(str.data, 8));
  token.slot = ntohs((u_short)ngx_hextoi_1(str.data+8, 4));
  token.pid = ntohs((u_short)ngx_hextoi_1(str.data+12, 4));
  token.time_stamp = ntohl((uint32_t)ngx_hextoi_1(str.data+16, 8));
  token.session_sequece = ntohl((uint32_t)ngx_hextoi_1(str.data+24, 8));
  
  return token;
}

static ngx_int_t ngx_stream_push_write_channel(ngx_socket_t s
                                               , ngx_stream_push_channel_t *ch
                                               , size_t size
                                               , ngx_log_t *log) {
  
  struct iovec        iov[1];
  iov[0].iov_base = ch;
  iov[0].iov_len = size;
  
  ssize_t n = writev(s, iov, 1);
  
  if (n == -1) {
    ngx_err_t err = ngx_errno;
    if (err == NGX_EAGAIN) {
      ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0
                     , "ngx_stream_push_write_channel ngx_again");
      return NGX_AGAIN;
    }
    
    ngx_log_error(NGX_LOG_ALERT, log, err, "ngx_stream_push_write_channel() failed");
    return NGX_ERROR;
  }
  
  ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0
                 , "ngx_stream_push_write_channel success");
  
  return NGX_OK;
  
}

static ngx_int_t ngx_stream_push_read_channel(ngx_socket_t s
                                              , ngx_stream_push_channel_t *ch
                                              , size_t size
                                              , ngx_log_t *log) {
  struct iovec        iov[1];
  iov[0].iov_base = ch;
  iov[0].iov_len = size;
  
  ssize_t n = readv(s, iov, 1);
  
  if (n == -1) {
    ngx_err_t err = ngx_errno;
    if (err == NGX_EAGAIN) {
      return NGX_AGAIN;
    }
    
    ngx_log_error(NGX_LOG_ALERT, log, err, "readv() failed");
    return NGX_ERROR;
  }
  
  if (n == 0) {
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "readv() returned zero");
    return NGX_ERROR;
  }
  
  if ((size_t) n < size) {
    ngx_log_error(NGX_LOG_ALERT, log, 0,
                  "recvmsg() returned not enough data: %z", n);
    return NGX_ERROR;
  }
  
  return NGX_OK;
}

#if defined ( __clang__ ) && defined ( __llvm__ )
#pragma mark - ipc
#endif

static ngx_int_t ngx_stream_push_ipc_init_module(ngx_cycle_t *cycle) {
  int         i, s = 0, on = 1;
  ngx_int_t   last_expected_process = ngx_last_process;
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(cycle, this_module);
  ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx
                                                          , ngx_core_module);
  ngx_int_t workers = ccf->worker_processes;
  
  /*
   * here's the deal: we have no control over fork()ing, nginx's internal
   * socketpairs are unusable for our purposes (as of nginx 0.8 -- check the
   * code to see why), and the module initialization callbacks occur before
   * any workers are spawned. Rather than futzing around with existing
   * socketpairs, we populate our own socketpairs array.
   * Trouble is, ngx_spawn_process() creates them one-by-one, and we need to
   * do it all at once. So we must guess all the workers' ngx_process_slots in
   * advance. Meaning the spawning logic must be copied to the T.
   */
  
  for(i=0; i<workers; i++) {
    while (s < last_expected_process && ngx_processes[s].pid != NGX_INVALID_FILE) {
      // find empty existing slot
      s++;
    }
    
    // copypaste from os/unix/ngx_process.c (ngx_spawn_process)
    ngx_socket_t    *socks = pmcf->socketpairs[s];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "socketpair() failed on socketpair while initializing push stream module");
      return NGX_ERROR;
    }
    if (ngx_nonblocking(socks[0]) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, ngx_nonblocking_n " failed on socketpair while initializing push stream module");
      ngx_close_channel(socks, cycle->log);
      return NGX_ERROR;
    }
    if (ngx_nonblocking(socks[1]) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, ngx_nonblocking_n " failed on socketpair while initializing push stream module");
      ngx_close_channel(socks, cycle->log);
      return NGX_ERROR;
    }
    if (ioctl(socks[0], FIOASYNC, &on) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "ioctl(FIOASYNC) failed on socketpair while initializing push stream module");
      ngx_close_channel(socks, cycle->log);
      return NGX_ERROR;
    }
    if (fcntl(socks[0], F_SETOWN, ngx_pid) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "fcntl(F_SETOWN) failed on socketpair while initializing push stream module");
      ngx_close_channel(socks, cycle->log);
      return NGX_ERROR;
    }
    if (fcntl(socks[0], F_SETFD, FD_CLOEXEC) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "fcntl(FD_CLOEXEC) failed on socketpair while initializing push stream module");
      ngx_close_channel(socks, cycle->log);
      return NGX_ERROR;
    }
    if (fcntl(socks[1], F_SETFD, FD_CLOEXEC) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "fcntl(FD_CLOEXEC) failed while initializing push stream module");
      ngx_close_channel(socks, cycle->log);
      return NGX_ERROR;
    }
    
    s++; // NEXT!!
  }
  
  return NGX_OK;
}

static ngx_int_t ngx_stream_push_ipc_init_process(ngx_cycle_t *cycle) {
  ngx_stream_request_push_main_conf_t* pmcf;
  pmcf = ngx_stream_cycle_get_module_main_conf(cycle, this_module);
  ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx
                                                          , ngx_core_module);
  ngx_int_t workers = ccf->worker_processes;
  
  int n = 0;
  for (n = 0; n < workers; n++) {
    
    if (ngx_processes[n].pid == -1) {
      continue;
    }
    
    if (n == ngx_process_slot) {
      continue;
    }
    
    if (ngx_processes[n].channel[1] == -1) {
      continue;
    }
    
    if (close(pmcf->socketpairs[n][1]) == -1) {
      ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    "close() channel failed");
      return NGX_ERROR;
    }
  }
  
  if (close(pmcf->socketpairs[ngx_process_slot][0]) == -1) {
    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                  "close() channel failed");
    return NGX_ERROR;
  }
  
  return ngx_add_channel_event(cycle, pmcf->socketpairs[ngx_process_slot][1]
                        , NGX_READ_EVENT, push_channel_event_handler_pt);
  
//  return NGX_OK;
}

