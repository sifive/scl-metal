/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_hash_sha512.h
 * @brief contains definitions of structures and primitives used for SHA512 and
 * HMAC-SHA512 implementation
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

#ifndef _SCL_SHA512_H
#define _SCL_SHA512_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>
#include <scl/scl_types.h>
#include <scl/scl_init.h>
#include <scl/scl_hash.h>


#define SCL_SHA512_BYTE_BLOCKSIZE 128
#define SCL_SHA512_ID 3
#define SCL_SHA512_BYTE_HASHSIZE 64
#define SCL_SHA512_ROUNDS_NUMBER 80
#define SCL_SHA512_H_SIZE 8
  //the nb of bytes for storing the size in the last block
#define SCL_SHA512_BYTE_SIZE_BLOCKSIZE 16
  struct scl_sha512_ctx
{
    // Initial, intermediate and then final hash.
    uint64_t h[SCL_SHA512_H_SIZE];
    // bit len
    uint64_t bitlen;
    // block buffer
    uint8_t block_buffer[SCL_SHA512_BYTE_BLOCKSIZE];
};

typedef struct scl_sha512_ctx scl_sha512_ctx_t;

  int scl_sha512(uint8_t *hash,uint8_t *data,int data_byte_len);
  int scl_sha512_init(scl_sha512_ctx_t *context);
  int scl_sha512_core(scl_sha512_ctx_t *context,uint8_t *data,int data_byteLen);
  void scl_sha512_block(scl_sha512_ctx_t *ctx,uint8_t *m);
  int scl_sha512_finish(uint8_t *hash,scl_sha512_ctx_t *context);
  int scl_hmac_sha512(uint8_t *mac,int mac_byte_len, uint8_t *message,int message_byte_len, uint8_t *key,int key_byte_len);
  int scl_hmac_sha512_init(scl_sha512_ctx_t *context , uint8_t *key, int key_byte_len);
  int scl_hmac_sha512_core(scl_sha512_ctx_t *context, uint8_t *data, int byte_len);
  int scl_hmac_sha512_finish(uint8_t *mac, int mac_byte_len, scl_sha512_ctx_t *context, uint8_t *key, int key_byte_len);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif//SCL_SHA512_H

