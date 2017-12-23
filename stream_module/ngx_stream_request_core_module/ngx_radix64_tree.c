//
//  ngx_radix64_tree.c
//  nginx-1.12
//
//  Created by xpwu on 2017/12/24.
//  Copyright © 2017年 xpwu. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_radix64_tree.h>


static ngx_radix_node_t *ngx_radix_alloc(ngx_radix_tree_t *tree);


ngx_int_t
ngx_radix64tree_insert(ngx_radix_tree_t *tree, uint64_t key, uint64_t mask,
                       uintptr_t value)
{
  uint64_t           bit;
  ngx_radix_node_t  *node, *next;
  
  bit = 0x8000000000000000;
  
  node = tree->root;
  next = tree->root;
  
  while (bit & mask) {
    if (key & bit) {
      next = node->right;
      
    } else {
      next = node->left;
    }
    
    if (next == NULL) {
      break;
    }
    
    bit >>= 1;
    node = next;
  }
  
  if (next) {
    if (node->value != NGX_RADIX_NO_VALUE) {
      return NGX_BUSY;
    }
    
    node->value = value;
    return NGX_OK;
  }
  
  while (bit & mask) {
    next = ngx_radix_alloc(tree);
    if (next == NULL) {
      return NGX_ERROR;
    }
    
    next->right = NULL;
    next->left = NULL;
    next->parent = node;
    next->value = NGX_RADIX_NO_VALUE;
    
    if (key & bit) {
      node->right = next;
      
    } else {
      node->left = next;
    }
    
    bit >>= 1;
    node = next;
  }
  
  node->value = value;
  
  return NGX_OK;
}


ngx_int_t
ngx_radix64tree_delete(ngx_radix_tree_t *tree, uint64_t key, uint64_t mask)
{
  uint64_t           bit;
  ngx_radix_node_t  *node;
  
  bit = 0x8000000000000000;
  node = tree->root;
  
  while (node && (bit & mask)) {
    if (key & bit) {
      node = node->right;
      
    } else {
      node = node->left;
    }
    
    bit >>= 1;
  }
  
  if (node == NULL) {
    return NGX_ERROR;
  }
  
  if (node->right || node->left) {
    if (node->value != NGX_RADIX_NO_VALUE) {
      node->value = NGX_RADIX_NO_VALUE;
      return NGX_OK;
    }
    
    return NGX_ERROR;
  }
  
  for ( ;; ) {
    if (node->parent->right == node) {
      node->parent->right = NULL;
      
    } else {
      node->parent->left = NULL;
    }
    
    node->right = tree->free;
    tree->free = node;
    
    node = node->parent;
    
    if (node->right || node->left) {
      break;
    }
    
    if (node->value != NGX_RADIX_NO_VALUE) {
      break;
    }
    
    if (node->parent == NULL) {
      break;
    }
  }
  
  return NGX_OK;
}


uintptr_t
ngx_radix64tree_find(ngx_radix_tree_t *tree, uint64_t key)
{
  uint64_t           bit;
  uintptr_t          value;
  ngx_radix_node_t  *node;
  
  bit = 0x8000000000000000;
  value = NGX_RADIX_NO_VALUE;
  node = tree->root;
  
  while (node) {
    if (node->value != NGX_RADIX_NO_VALUE) {
      value = node->value;
    }
    
    if (key & bit) {
      node = node->right;
      
    } else {
      node = node->left;
    }
    
    bit >>= 1;
  }
  
  return value;
}

static ngx_radix_node_t *
ngx_radix_alloc(ngx_radix_tree_t *tree)
{
  ngx_radix_node_t  *p;
  
  if (tree->free) {
    p = tree->free;
    tree->free = tree->free->right;
    return p;
  }
  
  if (tree->size < sizeof(ngx_radix_node_t)) {
    tree->start = ngx_pmemalign(tree->pool, ngx_pagesize, ngx_pagesize);
    if (tree->start == NULL) {
      return NULL;
    }
    
    tree->size = ngx_pagesize;
  }
  
  p = (ngx_radix_node_t *) tree->start;
  tree->start += sizeof(ngx_radix_node_t);
  tree->size -= sizeof(ngx_radix_node_t);
  
  return p;
}

