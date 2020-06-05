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

#ifndef _SHA256_H
#define _SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BYTE_BLOCKSIZE 64
#define SHA256_BYTE_HASHSIZE 32
#define SHA256_ROUNDS_NUMBER 64
/* number of words (32 bits) in hash */
#define SHA256_SIZE_WORDS 8
/** number of word in one block */
#define SHA256_BLOCK_WORDS 16
/* the nb of bytes for storing the size in the last block */
#define SHA256_BYTE_SIZE_BLOCKSIZE 8

typedef struct
{
    // intermediate state and then final hash
    uint32_t h[SHA256_SIZE_WORDS];
    // bits length
    uint64_t bitlen;
    // block buffer
    uint8_t block_buffer[SHA256_BYTE_BLOCKSIZE] __attribute__((aligned(4)));

} sha256_ctx_t;

#endif /* _SHA256_H */
