//
//  ngx_stream_encrypt_module.h
//  nginx1.10Xcode
//
//  Created by xpwu on 16/10/9.
//  Copyright © 2016年 xpwu. All rights reserved.
//

/*
 *  Because this is not real SSL, we call it 'ugly ssl'.
 *    when client has public key, we use ugly ssl.
 *
 *
 *
 *      RSA1024_PKCS1_OAEP_PADDING + AES128_CBC_PKCS7PADDING
 *
 *            client -------------------------------- server
 *              |                                        |
 *              |                                        |
 *   RSA[random<16> + checksum + random<10>] -----> RSA'[random<16> + checksum + random<10>]
 *              |                                        |
 *              |                                        |
 *              |                                     checksum ---N-->close connection
 *              |                                        |
 *              |                                        Y
 *              |                                        |
 *     RSA'[checksum[random<10>]]  <-----  RSA[checksum[random<10>]]
 *              |                                        |
 *              |                                        |
 *           checksum ---N-->close connection            |
 *              |                                        |
 *              Y                                        |
 *              |                                        |
 *     iv = aes_key = random<16>               iv = aes_key = random<16>
 *              |                                        |
 *              +---------- handshake success -----------+
 *              :                                        :
 *              :                                        :
 *           data|HMAC    <------------------->    data|HMAC
 *              :                                        :
 *
 *     checksum = random[0] ^ random[1] ^ ... ^ 0xff
 *     RSA len suggest 1024
 *
 *     (data, iv) = AES128(aes_key, app_data + padding, iv);
 *     HMAC = hmac_md5(aes_key, app_data + peer_serial_no<string>)
 *     sizeof(HMAC) = 16;
 *     peer_serial_no : init = 0; every ssl chunk inc 1, uint32_t type.
 *
 */


#ifndef ngx_stream_encrypt_module_h
#define ngx_stream_encrypt_module_h

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

/**
 * return value:
 *  NGX_OK --- handshake over
 *  NGX_AGAIN --- handshake again
 *  NGX_ERROR --- error
 *  NGX_DECLINED --- not need handshake
 */

extern ngx_int_t ngx_stream_encrypt_handshake_size(ngx_stream_session_t* s);
extern ngx_int_t ngx_stream_encrypt_handshake(ngx_stream_session_t* s
                                              , ngx_buf_t* buffer_in
                                              , ngx_buf_t* buffer_out
                                              );

extern ngx_int_t ngx_stream_encrypt_size(ngx_int_t plantext_size);
extern ngx_int_t ngx_stream_encrypt_buffer(ngx_stream_session_t* s
                                           , ngx_buf_t* buffer_in
                                           , ngx_buf_t* buffer_out
                                           );

extern ngx_int_t ngx_stream_decrypt_max_size(ngx_int_t enctext_size);
extern ngx_int_t ngx_stream_decrypt_buffer(ngx_stream_session_t* s
                                           , ngx_buf_t* buffer_in
                                           , ngx_buf_t* buffer_out
                                           );


#endif /* ngx_stream_encrypt_module_h */
