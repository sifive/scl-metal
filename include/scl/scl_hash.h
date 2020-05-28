/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_hash.h
 * @brief these defines are used to select or not hash functions useful on 
 * platforms with limited resources
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

#ifndef _SCL_HASH_H
#define _SCL_HASH_H

#define SCL_HASH_SHA256 //SCL_SHA256 = 1
#define SCL_HASH_SHA384 //SCL_SHA384 = 2
#define SCL_HASH_SHA224 //SCL_SHA224 = 4
#define SCL_HASH_SHA512 //SCL_SHA512 = 3
//#define SCL_HASH_SHA3
//#define SCL_HASH_SHA3_224
//#define SCL_HASH_SHA3_256
//#define SCL_HASH_SHA3_384
//#define SCL_HASH_SHA3_512
#define SCL_HASH_FUNCTIONS_MAX_NB 9
#define SCL_UNDEFINED_HASH -1
#define SCL_HASH_BYTE_DIGEST_MAXSIZE 64
#define SCL_HASH_BYTE_BLOCK_MAXSIZE 128
#ifdef SCL_HCA_SHA_ON
#define SCL_HASH_HCA_SHA224 0
#define SCL_HASH_HCA_SHA256 1
#define SCL_HASH_HCA_SHA384 2
#define SCL_HASH_HCA_SHA512 3
#define SCL_HCA_SHA_TARGET 1
#endif

#endif //_SCL_HASH_H
