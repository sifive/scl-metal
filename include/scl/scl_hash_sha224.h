/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_hash_sha224.h
 * @brief contains definitions of structures and primitives used for SHA224 and
 * HMAC-SHA224 implementation
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 ******************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 ******************************************************************************/

#ifndef _SCL_SHA224_H
#define _SCL_SHA224_H
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>
#include <scl/scl_types.h>
#include <scl/scl_init.h>
#include <scl/scl_hash.h>
  
//because SHA224 is a truncation of SHA256
#include <scl/scl_hash_sha256.h>

typedef struct scl_sha256_ctx scl_sha224_ctx_t;

#define SCL_SHA224_BYTE_BLOCKSIZE 64
#define SCL_SHA224_ID 4
#define SCL_SHA224_BYTE_HASHSIZE 28
  //the nb of bytes for storing the size in the last block
#define SCL_SHA224_BYTE_SIZE_BLOCKSIZE 8

int scl_sha224(uint8_t *hash, uint8_t *data, word_type data_byte_len);
int scl_sha224_init(scl_sha224_ctx_t *context);
int scl_sha224_core(scl_sha224_ctx_t *context, uint8_t *data, word_type data_byte_len);
int scl_sha224_finish(uint8_t *hash, scl_sha224_ctx_t *context);
  
int scl_hmac_sha224(uint8_t *mac, word_type mac_byte_len, uint8_t *message, word_type message_byte_len, uint8_t *key, word_type key_byte_len);
int scl_hmac_sha224_init(scl_sha224_ctx_t *context , uint8_t *key, word_type key_byte_len);
int scl_hmac_sha224_core(scl_sha224_ctx_t *context, uint8_t *message, word_type message_byte_len);
int scl_hmac_sha224_finish(uint8_t *mac, word_type mac_byteLen, scl_sha224_ctx_t *context, uint8_t *key, word_type key_byte_len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif//_SCL_SHA224_H
