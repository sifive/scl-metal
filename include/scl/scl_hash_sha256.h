/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_hash_sha256.h
 * @brief contains definitions of structures and primitives used for SHA256 and
 * HMAC-SHA256 implementation
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

#ifndef _SCL_SHA256_H
#define _SCL_SHA256_H

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>
#include <scl/scl_types.h>
#include <scl/scl_init.h>
#include <scl/scl_hash.h>

#ifdef __cplusplus
extern "C" {
#endif // _ cplusplus

#define SCL_SHA256_BYTE_BLOCKSIZE 64
#define SCL_SHA256_ID 1
#define SCL_SHA256_BYTE_HASHSIZE 32
#define SCL_SHA256_ROUNDS_NUMBER 64
#define SCL_SHA256_H_SIZE 8
  //the nb of bytes for storing the size in the last block
#define SCL_SHA256_BYTE_SIZE_BLOCKSIZE 8
  struct scl_sha256_ctx
  {
    // intermediate state and then final hash
    uint32_t h[SCL_SHA256_H_SIZE];
    // bits length
    uint64_t bitlen;
    // block buffer
    uint8_t block_buffer[SCL_SHA256_BYTE_BLOCKSIZE];
  };
  
typedef struct scl_sha256_ctx scl_sha256_ctx_t;

  int scl_sha256(uint8_t *hash, uint8_t *data, int data_byte_len);
  int scl_sha256_init(scl_sha256_ctx_t *context);
  int scl_sha256_core(scl_sha256_ctx_t *context, uint8_t *data, int data_byte_len);
  void scl_sha256_block(scl_sha256_ctx_t *context,uint8_t *m);
  int scl_sha256_finish(uint8_t *hash, scl_sha256_ctx_t *context);

  int scl_hmac_sha256(uint8_t *mac,int mac_byte_len, uint8_t *message,int message_byte_len, uint8_t *key,int key_byte_len);
  int scl_hmac_sha256_init(scl_sha256_ctx_t *context , uint8_t *key, int key_byte_len);
  int scl_hmac_sha256_core(scl_sha256_ctx_t *context, uint8_t *data, int byte_len);
  int scl_hmac_sha256_finish(uint8_t *mac, int mac_byte_len, scl_sha256_ctx_t *context, uint8_t *key, int key_byte_len);
  
#ifdef __cplusplus
}
#endif // _ cplusplus

#endif // _SCL_SHA256_H
