//
//  ngx_radix64_tree.h
//  nginx-1.12
//
//  Created by xpwu on 2017/12/24.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#ifndef ngx_radix64_tree_h
#define ngx_radix64_tree_h

#include <ngx_config.h>
#include <ngx_core.h>

ngx_int_t ngx_radix64tree_insert(ngx_radix_tree_t *tree,
                                 uint64_t key, uint64_t mask, uintptr_t value);
ngx_int_t ngx_radix64tree_delete(ngx_radix_tree_t *tree,
                                 uint64_t key, uint64_t mask);
uintptr_t ngx_radix64tree_find(ngx_radix_tree_t *tree, uint64_t key);


#endif /* ngx_radix64_tree_h */
