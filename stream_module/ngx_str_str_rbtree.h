//
//  ngx_str_str_rbtree.h
//  ngx-1.10.1-xcode
//
//  Created by xpwu on 2016/11/18.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#ifndef ngx_str_str_rbtree_h
#define ngx_str_str_rbtree_h

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct{
  ngx_rbtree_t tree;
  ngx_rbtree_node_t sentinel;
  ngx_pool_t* pool;
  ngx_log_t* log;
} ngx_str_str_rbtree;

extern void ngx_str_str_rbtree_init(ngx_str_str_rbtree* tree
                                    , ngx_pool_t* pool, ngx_log_t* log);

extern ngx_str_t ngx_str_str_rbtree_get_value(ngx_str_str_rbtree* tree
                                              , ngx_str_t key);
extern void ngx_str_str_rbtree_set_value(ngx_str_str_rbtree* tree
                                         , ngx_str_t key
                                         , ngx_str_t value
                                         , ngx_int_t force_rewrite);

#define ngx_str_str_rbtree_is_empty(rbtree_ptr) \
  ((tree_ptr)->tree->root == (tree_ptr)->tree->sentinel ? 1 : 0);

#endif /* ngx_str_str_rbtree_h */
