/****************************************************************************** 
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * Copyright 2020 SiFive, Inc
 * SPDX-License-Identifier: MIT
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

/*
 * file: scl_aes_ecb.h
 * 
 * defines the AES for the ECB mode
 * AES is NIST FIPS-197, ECB is SP800-38A
 */

#ifndef _SCL_AES_ECB_H
#define _SCL_AES_ECB_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
  int scl_aes_ecb(uint8_t *dst, uint8_t *src, int src_byte_len, uint8_t *key, int key_byte_len, int mode);
  int scl_aes_ecb_init(uint8_t *key,int key_byte_len, int mode);
  int scl_aes_ecb_core(uint8_t *dst, uint8_t *src, int src_byte_len, int mode);
  int scl_aes_ecb_finish(void);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif //_SCL_AES_ECB_H