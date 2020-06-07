/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file sha512.h
 * @brief sha512 implementation/wrapper
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

#ifndef _SHA512_H
#define _SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_BYTE_BLOCKSIZE 128
#define SHA512_BYTE_HASHSIZE 64
#define SHA512_ROUNDS_NUMBER 80
/* number of words (64 bits) in hash */
#define SHA512_SIZE_WORDS 8
/** number of word (64 bits) in one block */
#define SHA512_BLOCK_WORDS 16
/* the nb of bytes for storing the size in the last block */
#define SHA512_BYTE_SIZE_BLOCKSIZE 16

typedef struct
{
    // Initial, intermediate and then final hash.
    uint64_t h[SHA512_SIZE_WORDS];
    // bit len
    uint64_t bitlen;
    // block buffer
    uint8_t block_buffer[SHA512_BYTE_BLOCKSIZE] __attribute__((aligned(8)));
} sha512_ctx_t;

#endif
