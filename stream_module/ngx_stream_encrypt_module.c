//
//  ngx_stream_encrypt_module.c
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/9.
//  Copyright © 2016年 xpwu. All rights reserved.
//

#include "ngx_stream_encrypt_module.h"


#ifdef this_module
#undef this_module
#endif
#define this_module ngx_stream_encrypt_module

#if (!NGX_STREAM_SSL)
#error has not define NGX_STREAM_SSL
#endif

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ngx_event_openssl.h>

static void *ngx_stream_encrypt_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_encrypt_merge_srv_conf(ngx_conf_t *cf
                                              , void *parent
                                              , void *child);
static char *ngx_stream_encrypt_password_file(ngx_conf_t *cf
                                               , ngx_command_t *cmd, void *conf);

typedef struct {
  ngx_str_t     private_file;
  ngx_array_t*  passwords;
  RSA*          rsa;
}encrypt_srv_conf_t;

static ngx_command_t  ngx_stream_encrypt_commands[] = {
  
  { ngx_string("encrypt_privatekey_file"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_STREAM_SRV_CONF_OFFSET,
    offsetof(encrypt_srv_conf_t, private_file),
    NULL },
  
  { ngx_string("encrypt_privatekey_passwd_file"),
    NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
    ngx_stream_encrypt_password_file,
    NGX_STREAM_SRV_CONF_OFFSET,
    0,
    NULL },
  
  ngx_null_command
};


static ngx_stream_module_t  ngx_stream_encrypt_module_ctx = {
  NULL,            /* postconfiguration */
  
  NULL,                               /* create main configuration */
  NULL,                                  /* init main configuration */
  
  ngx_stream_encrypt_create_srv_conf,   /* create server configuration */
  ngx_stream_encrypt_merge_srv_conf     /* merge server configuration */
};


ngx_module_t  ngx_stream_encrypt_module = {
  NGX_MODULE_V1,
  &ngx_stream_encrypt_module_ctx,           /* module context */
  ngx_stream_encrypt_commands,              /* module directives */
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

static void *ngx_stream_encrypt_create_srv_conf(ngx_conf_t *cf) {
  encrypt_srv_conf_t  *usscf;
  
  usscf = ngx_pcalloc(cf->pool, sizeof(encrypt_srv_conf_t));
  if (usscf == NULL) {
    return NULL;
  }
  
  /*
   * set by ngx_pcalloc():
   * usscf->rsa = NULL
   * usscf->private_file = { 0, NULL };
   */
  
  usscf->passwords = NGX_CONF_UNSET_PTR;
  
  return usscf;
}

static int privatekey_passwd(char *buf, int size, int rwflag, void *userdata) {
  /***
   *
   *   copy from ngx_event_openssl.c --- 'ngx_ssl_password_callback'
   *
   */
  ngx_str_t *pwd = userdata;
  
  if (rwflag) {
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                  "privatekey_passwd() is called for encryption");
    return 0;
  }
  
  if ((int)pwd->len > size) {
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "password is truncated to %d bytes", size);
  } else {
    size = (int)pwd->len;
  }
  
  ngx_memcpy(buf, pwd->data, size);
  
  return size;
}

static char *ngx_stream_encrypt_merge_srv_conf(ngx_conf_t *cf
                                                , void *parent, void *child) {
  encrypt_srv_conf_t *prev = parent;
  encrypt_srv_conf_t *conf = child;
  
  ngx_conf_merge_str_value(conf->private_file, prev->private_file, "");
  ngx_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);
  
  BIO         *bio;
  bio = BIO_new_file((char *) conf->private_file.data, "r");
  if (bio == NULL) {
    return "encrypt bio is null";
  }
  OpenSSL_add_all_algorithms();
  
  ngx_str_t   *pwd = conf->passwords->elts;
  ngx_uint_t   tries = conf->passwords->nelts;
  for (;;) {
    conf->rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, privatekey_passwd, pwd);
    if (conf->rsa != NULL) {
      break;
    }
    if (--tries) {
      ERR_clear_error();
      ++pwd;
      continue;
    }
    
    return "encrypt rsa is null";
  }
  
  BIO_free(bio);
  if (conf->rsa == NULL) {
    return "encrypt rsa is null";
  }
  
  return NGX_CONF_OK;
}

static char *ngx_stream_ugly_ssl_password_file(ngx_conf_t *cf
                                               , ngx_command_t *cmd, void *conf) {
  
  encrypt_srv_conf_t  *scf = conf;
  
  ngx_str_t  *value;
  
  if (scf->passwords != NGX_CONF_UNSET_PTR) {
    return "is duplicate";
  }
  
  value = cf->args->elts;
  
  scf->passwords = ngx_ssl_read_password_file(cf, &value[1]);
  
  if (scf->passwords == NULL) {
    return NGX_CONF_ERROR;
  }
  
  return NGX_CONF_OK;
}

#pragma mark - handlers

#define AES_KEY_LEN  (128/8)
#define RSA_DATA_LEN (AES_KEY_LEN + 1 + 10)
#define HMAC_MD5_SIZE 16


typedef struct{
  ngx_pool_t* pool;
  ngx_buf_t* buffer;
} encrypt_temp_buffer_t;

typedef struct ngx_stream_session_ugly_ssl_ctx_s {
  AES_KEY   decryptKey;
  AES_KEY   encryptKey;
  uint32_t  peer_serial_no; // send
  uint32_t  my_serial_no; // check recv
  uint8_t   peer_iv[AES_KEY_LEN]; // decrypt iv
  uint8_t   my_iv[AES_KEY_LEN]; // encrypt_iv
  
  HMAC_CTX  hmac_ctx;
  encrypt_temp_buffer_t* temp_buffer;
}ngx_stream_encrypt_ctx_t;

static ngx_stream_encrypt_ctx_t* get_ctx(ngx_stream_session_t* s) {
  ngx_stream_encrypt_ctx_t* ctx = ngx_stream_get_module_ctx(s, this_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_encrypt_ctx_t));
    /**
     *  ngx_pcalloc set:
     *  ctx->peer_serial_no = 0;
     *  ctx->my_serial_no = 0;
     *  ctx->temp_buffer = NULL;
     */
//    HMAC_CTX_init(&ctx->recv_hmac_ctx);
//    HMAC_CTX_init(&ctx->send_hmac_ctx);
    ngx_stream_set_ctx(s, ctx, this_module);
  }
  return ctx;
}

#define ngx_buf_left_size(b) \
  (ngx_buf_in_memory(b) ? (off_t) (b->end - b->last):  0)

extern ngx_int_t ngx_stream_encrypt_handshake_size(ngx_stream_session_t* s) {
  encrypt_srv_conf_t* escf = ngx_stream_get_module_srv_conf(s, this_module);
  return RSA_size(escf->rsa);
}

#define this_min(a, b) (a) < (b) ? (a) : (b)

extern ngx_int_t ngx_stream_encrypt_handshake(ngx_stream_session_t* s
                                              , ngx_buf_t* buffer_in
                                              , ngx_buf_t* buffer_out) {
  ngx_stream_encrypt_ctx_t* ctx = get_ctx(s);
  encrypt_srv_conf_t* escf = ngx_stream_get_module_srv_conf(s, this_module);
  
  if (ngx_buf_left_size(buffer_out) < RSA_size(escf->rsa)) {
    if (ctx->temp_buffer && ctx->temp_buffer->pool) {
      ngx_destroy_pool(ctx->temp_buffer->pool);
      ctx->temp_buffer = NULL;
    }
    return NGX_ERROR;
  }
  
  if (ctx->temp_buffer == NULL) {
    ngx_pool_t* pool = ngx_create_pool(RSA_size(escf->rsa) + 500
                                       , s->connection->log);
    ctx->temp_buffer = ngx_pcalloc(pool, sizeof(encrypt_temp_buffer_t));
    ctx->temp_buffer->buffer = ngx_create_temp_buf(pool, RSA_size(escf->rsa));
    ctx->temp_buffer->pool = pool;
  }
  size_t len = this_min(buffer_in->last - buffer_in->pos
                        , ctx->temp_buffer->buffer->end - ctx->temp_buffer->buffer->last);
  ngx_memcpy(ctx->temp_buffer->buffer->last, buffer_in->pos, len);
  ctx->temp_buffer->buffer->last += len;
  buffer_in->pos += len;
  if (ctx->temp_buffer->buffer->last != ctx->temp_buffer->buffer->end) {
    return NGX_AGAIN;
  }
  
  int res = RSA_private_decrypt(RSA_size(escf->rsa)
                                , ctx->temp_buffer->buffer->pos
                                , buffer_out->last, escf->rsa
                                , RSA_PKCS1_OAEP_PADDING);
  
  ngx_destroy_pool(ctx->temp_buffer->pool);
  ctx->temp_buffer = NULL;
  
  if (res != RSA_DATA_LEN) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "symmetry key len is %d, not %d"
                  , res, RSA_DATA_LEN);
    return NGX_ERROR;
  }
  
#if (NGX_DEBUG)
  ngx_log_t* log = s->connection->log;
  u_char hex[2*AES_KEY_LEN];
  ngx_hex_dump(hex, buffer_out->last, AES_KEY_LEN);
  ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0
                 , "symmetry key = %*s", 2*AES_KEY_LEN, hex);
#endif
  
  uint8_t xor = 0;
  for (int i = 0; i < AES_KEY_LEN + 1; ++i) {
    xor ^= buffer_out->last[i];
  }
  if (xor != 0xff) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "symmetry key checksum error");
    return NGX_ERROR;
  }
  
  ngx_memcpy(ctx->my_iv, buffer_out->last, AES_KEY_LEN);
  ngx_memcpy(ctx->peer_iv, buffer_out->last, AES_KEY_LEN);
  res = AES_set_encrypt_key(buffer_out->last, AES_KEY_LEN*8, &ctx->encryptKey);
  if (res < 0) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "AES_set_encrypt_key error");
    return NGX_ERROR;
  }
  res = AES_set_decrypt_key(buffer_out->last, AES_KEY_LEN*8, &ctx->decryptKey);
  if (res < 0) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "AES_set_decrypt_key error");
    return NGX_ERROR;
  }
  
  HMAC_CTX_init(&ctx->hmac_ctx);
  if (!HMAC_Init_ex(&ctx->hmac_ctx, buffer_out->last, AES_KEY_LEN, EVP_md5(), NULL)) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "HMAC_Init_ex error");
    return NGX_ERROR;
  }
  
  //send sign
  xor = 0;
  for (int i = AES_KEY_LEN + 1; i < RSA_DATA_LEN; ++i) {
    xor ^= buffer_out->last[i];
  }
  xor ^= 0xff;
  res = RSA_private_encrypt(1, &xor, buffer_out->pos
                            , escf->rsa, RSA_PKCS1_OAEP_PADDING);
  buffer_out->last += res;
  
  return NGX_OK;
}

extern ngx_int_t ngx_stream_encrypt_size(ngx_int_t plantext_size) {
  return HMAC_MD5_SIZE + AES_BLOCK_SIZE
    - plantext_size%AES_BLOCK_SIZE + plantext_size;
}

extern ngx_int_t ngx_stream_encrypt_buffer(ngx_stream_session_t* s
                                           , ngx_buf_t* buffer_in
                                           , ngx_buf_t* buffer_out
                                           ) {
  if (ngx_stream_encrypt_size(ngx_buf_size(buffer_in)) >
      ngx_buf_left_size(buffer_out)) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "ngx_stream_encrypt_buffer buffer_out is too small");
    return NGX_ERROR;
  }
  ngx_stream_encrypt_ctx_t* ctx = get_ctx(s);
  
  int firstLen = (int)ngx_buf_size(buffer_in)
      - (int)ngx_buf_size(buffer_in)%AES_BLOCK_SIZE;
  AES_cbc_encrypt(buffer_in->pos, buffer_out->last, firstLen
                  , &ctx->encryptKey, ctx->my_iv, 1);
  buffer_out->last += firstLen;
  int padding = AES_BLOCK_SIZE - (int)ngx_buf_size(buffer_in)%AES_BLOCK_SIZE;
  u_char pad[AES_BLOCK_SIZE];
  ngx_memset(pad, padding, AES_BLOCK_SIZE);
  if (firstLen != (int)ngx_buf_size(buffer_in)) {
    ngx_memcpy(pad, buffer_in->pos+firstLen, padding);
  }
  AES_cbc_encrypt(pad, buffer_out->last, AES_BLOCK_SIZE
                  , &ctx->encryptKey, ctx->my_iv, 1);
  buffer_out->last += AES_BLOCK_SIZE;
  
  HMAC_Init_ex(&ctx->hmac_ctx, NULL, 0, NULL, NULL);
  HMAC_Update(&ctx->hmac_ctx, buffer_in->pos, (int)ngx_buf_size(buffer_in));
  u_char serial_str[11];
  ctx->peer_serial_no++;
  u_char* end = ngx_sprintf(serial_str, "%ud", ctx->peer_serial_no);
  HMAC_Update(&ctx->hmac_ctx, serial_str, end-serial_str);
  unsigned char hmac[HMAC_MAX_MD_CBLOCK];
  unsigned int hmac_len = HMAC_MAX_MD_CBLOCK;
  HMAC_Final(&ctx->hmac_ctx, hmac, &hmac_len);
  if (hmac_len > HMAC_MD5_SIZE) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "hmac length is error, which is %d, but should be %d"
                  , hmac_len, HMAC_MD5_SIZE);
    return NGX_ERROR;
  }
  ngx_memcpy(buffer_out->last, hmac, hmac_len);
  buffer_out->last += hmac_len;
  
  return NGX_OK;
}

extern ngx_int_t ngx_stream_decrypt_max_size(ngx_int_t enctext_size) {
  return enctext_size - HMAC_MD5_SIZE;
}

extern ngx_int_t ngx_stream_decrypt_buffer(ngx_stream_session_t* s
                                           , ngx_buf_t* buffer_in
                                           , ngx_buf_t* buffer_out
                                           ) {
  if (ngx_stream_decrypt_max_size(ngx_buf_size(buffer_in)) >
      ngx_buf_left_size(buffer_out)) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "ngx_stream_decrypt_buffer buffer_out is too small");
    return NGX_ERROR;
  }
  ngx_stream_encrypt_ctx_t* ctx = get_ctx(s);
  
  AES_cbc_encrypt(buffer_in->pos, buffer_out->last
                  , (int)ngx_buf_size(buffer_in)-HMAC_MD5_SIZE
                  , &ctx->decryptKey, ctx->peer_iv, 0);
  u_char* p = buffer_out->last;
  buffer_out->last += (int)ngx_buf_size(buffer_in)-HMAC_MD5_SIZE;
  buffer_out->last -= *(buffer_out->last-1);
  
  HMAC_Init_ex(&ctx->hmac_ctx, NULL, 0, NULL, NULL);
  HMAC_Update(&ctx->hmac_ctx, p
              , (int)(buffer_out->last - p));
  
  buffer_in->pos += (int)ngx_buf_size(buffer_in)-HMAC_MD5_SIZE;
  
  u_char serial_str[11];
  ctx->my_serial_no++;
  u_char* end = ngx_sprintf(serial_str, "%ud", ctx->my_serial_no);
  HMAC_Update(&ctx->hmac_ctx, serial_str, end-serial_str);
  unsigned char hmac[HMAC_MAX_MD_CBLOCK];
  unsigned int hmac_len = HMAC_MAX_MD_CBLOCK;
  HMAC_Final(&ctx->hmac_ctx, hmac, &hmac_len);
  // hmac_len == HMAC_size(&ctx->recv_hmac_ctx);
  if (ngx_memcmp(hmac, buffer_in->pos, hmac_len) != 0) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0
                  , "hmac length is error, which is %d, but should be %d"
                  , hmac_len, HMAC_MD5_SIZE);
    return NGX_ERROR;
  }

  return NGX_OK;
}






