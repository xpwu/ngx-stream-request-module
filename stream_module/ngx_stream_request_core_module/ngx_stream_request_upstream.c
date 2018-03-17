//
//  ngx_stream_request_upstream.c
//  nginx-1.12
//
//  Created by xpwu on 2017/12/16.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream_request.h>

static void ngx_stream_request_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_request_core_test_connect(ngx_connection_t *c);
static void ngx_stream_request_core_next_upstream(ngx_stream_request_t *r);
static void ngx_stream_proxy_init_upstream(ngx_stream_request_t *r);

static void empty_handler(ngx_event_t *ev){}

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
  
  u = &r->upstream->upstream;
  
  if (u->peer.sockaddr) {
    u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
    u->peer.sockaddr = NULL;
  }
  
  pscf = ngx_stream_get_module_srv_conf(r->session, ngx_stream_request_core_module);
  
  timeout = pscf->next_upstream_timeout;
  
  if (u->peer.tries == 0
      || !pscf->next_upstream
      || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
  {
    r->upstream->upstream_connect_failed(r, "has not upstream");
    return;
  }
  
  pc = u->peer.connection;
  
  if (pc) {
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->session->connection->log, 0,
                   "close proxy upstream connection: %d", pc->fd);
    
    ngx_close_connection(pc);
    u->peer.connection = NULL;
  }
  
  ngx_stream_request_upstream_connect(r);
}

void
ngx_stream_request_upstream_connect(ngx_stream_request_t *r)
{
  ngx_int_t                     rc;
  ngx_connection_t             *c, *pc;
  ngx_stream_upstream_t        *u;
  ngx_stream_request_core_srv_conf_t  *pscf;
  ngx_stream_session_t* s;
  
  s = r->session;
  c = s->connection;
  
//  c->log->action = "";
  
  u = &r->upstream->upstream;
  
  rc = ngx_event_connect_peer(&u->peer);
  
  
#ifdef NGX_DEBUG
  char* rc_s = "";
  switch (rc) {
    case -1:
      rc_s = "NGX_ERROR";
      break;
    case -2:
      rc_s = "NGX_AGAIN";
      break;
    case -3:
      rc_s = "NGX_BUSY";
      break;
    default:
      rc_s = "-4: NGX_DONE; -5:NGX_DECLINED; -6:NGX_ABORT";
      break;
  }
#endif
  
  ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0
                 , "proxy connect: %i, %s", rc, rc_s);
  
  if (rc == NGX_ERROR) {
    r->upstream->upstream_connect_failed(r, "connect upsteam peer error");
    return;
  }
  
  if (rc == NGX_BUSY) {
    r->upstream->upstream_connect_failed(r, "no live upstreams");
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
  
  pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_request_core_module);
  
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
  ngx_stream_session_t* s = r->session;
  
  u = &r->upstream->upstream;
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
  
  u->connected = 1;
  
  pc->read->handler = empty_handler;
  pc->write->handler = empty_handler;
  
  r->upstream->upstream_connected(r);
}

static void
ngx_stream_request_proxy_connect_handler(ngx_event_t *ev)
{
  ngx_connection_t      *c;
  //  ngx_stream_session_t  *s;
  ngx_stream_request_t* r;
  
  c = ev->data;
  r = c->data;
  //  s = r->session;
  
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


