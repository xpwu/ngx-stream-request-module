//
//  ngx_str_str_rbtree.c
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/11/18.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include <ngx_str_str_rbtree.h>

#ifndef ngx_str_str_rbtree_c
#define ngx_str_str_rbtree_c

typedef struct{
  ngx_str_node_t node; // must be first, not be pointer
  ngx_str_t value;
} ngx_str_str_rbtree_node_t;

extern void ngx_str_str_rbtree_init(ngx_str_str_rbtree* tree
                                    , ngx_pool_t* pool, ngx_log_t* log) {
  ngx_rbtree_init(&tree->tree, &tree->sentinel
                  , ngx_str_rbtree_insert_value);
  tree->pool = pool;
  tree->log = log;
}

//#if (NGX_DEBUG)
//static void print_rbtree(ngx_rbtree_node_t* root
//                         , ngx_rbtree_node_t* sentinel
//                         , u_char** buf, u_char* last, ngx_int_t* end) {
//  if (root == sentinel) {
//    return;
//  }
//
//  if (*end == 1) {
//    return;
//  }
//
//  print_rbtree(root->left, sentinel, buf, last, end);
//
//  ngx_str_str_rbtree_node_t* node = (ngx_str_str_rbtree_node_t*)root;
//  if (*buf + node->node.str.len + node->value.len + 4 > last) {
//    *buf = ngx_cpymem(*buf, ";...", 4);
//    *end = 1;
//  } else {
//    *buf = ngx_cpymem(*buf, node->node.str.data, node->node.str.len);
//    *buf = ngx_cpymem(*buf, ": ", 2);
//    *buf = ngx_cpymem(*buf, node->value.data, node->value.len);
//    *buf = ngx_cpymem(*buf, "; ", 2);
//  }
//
//  print_rbtree(root->right, sentinel, buf, last, end);
//}
//#endif

extern ngx_str_t ngx_str_str_rbtree_get_value(ngx_str_str_rbtree* tree
                                              , ngx_str_t key) {
//#if (NGX_DEBUG)
//  ngx_log_t* log = tree->log;
//  u_char allVar[1024];
//  u_char* last = allVar + 1024;
//  u_char* buf = allVar;
//  ngx_int_t end = 0;
//  print_rbtree(tree->tree.root, tree->tree.sentinel, &buf, last, &end);
//  ngx_log_debug3(NGX_LOG_DEBUG_STREAM, log, 0
//                 , "ngx str_str_rbtree<%p> all variable is {%*s}"
//                 , tree, buf-allVar, allVar);
//#endif
  
  ngx_str_t res = ngx_null_string;
  
  ngx_str_node_t* node = ngx_str_rbtree_lookup(&tree->tree, &key, 0);
  if (node == NULL) {
    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, tree->log, 0
                   , "ngx str_str_rbtree<%p> get var(%V) is null"
                   , tree, &key);
    return res;
  }
  
  ngx_str_str_rbtree_node_t* vnode = (ngx_str_str_rbtree_node_t*)node;
  ngx_log_debug3(NGX_LOG_DEBUG_STREAM, tree->log, 0
                 , "ngx str_str_rbtree<%p> get var(%V) is (%V)"
                 , tree, &key, &vnode->value);
  return vnode->value;
}

extern void ngx_str_str_rbtree_set_value(ngx_str_str_rbtree* tree
                                         , ngx_str_t key
                                         , ngx_str_t value
                                         , ngx_int_t force_rewrite) {
  ngx_str_str_rbtree_node_t* vnode;
  
  ngx_str_node_t* node = ngx_str_rbtree_lookup(&tree->tree, &key, 0);
  
  if (node != NULL && force_rewrite == 0) {
//#if (NGX_DEBUG)
//    ngx_str_str_rbtree_node_t* vnode = (ngx_str_str_rbtree_node_t*)node;
//    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, tree->log, 0
//                   , "ngx str_str_rbtree<%p> key(%V) has value (%V) yet"
//                   ,tree, &key, &vnode->value);
//#endif
    return;
  }
  
  if (node != NULL) {
    vnode = (ngx_str_str_rbtree_node_t*)node;
    if (vnode->value.len >= value.len) {
      ngx_memcpy(vnode->value.data, value.data, value.len);
    } else {
      ngx_pfree(tree->pool, vnode->value.data);
      vnode->value.data = ngx_pcalloc(tree->pool, value.len);
      ngx_memcpy(vnode->value.data, value.data, value.len);
    }
    vnode->value.len = value.len;
    return;
  }
  
  vnode = ngx_pcalloc(tree->pool, sizeof(ngx_str_str_rbtree_node_t));
  /**
   * set by ngx_pcalloc:
   * vnode->node.node.key = 0;
   */
  vnode->value.data = ngx_pcalloc(tree->pool, value.len);
  ngx_memcpy(vnode->value.data, value.data, value.len);
  vnode->value.len = value.len;
  
  vnode->node.str.len = key.len;
  vnode->node.str.data = ngx_pcalloc(tree->pool, key.len);
  ngx_memcpy(vnode->node.str.data, key.data, key.len);
  
  ngx_rbtree_insert(&tree->tree, (ngx_rbtree_node_t*)vnode);
}

#endif //~ngx_str_str_rbtree_c
