/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file soft_sha512.h
 * @brief software sha512 implementation
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

#ifndef _SOFT_SHA512_H
#define _SOFT_SHA512_H

#include <stdint.h>

#include <crypto_cfg.h>

#include <api/defs.h>
#include <api/hash/sha.h>
#include <api/hash/sha512.h>

CRYPTO_FUNCTION int32_t sha512_block_soft(sha512_ctx_t *const ctx,
                                          const uint8_t *const words);

CRYPTO_FUNCTION int32_t sha512_init_soft(sha512_ctx_t *const ctx,
                                         endianness_t data_endianness);

CRYPTO_FUNCTION int32_t sha512_core_soft(sha512_ctx_t *const ctx,
                                         const uint8_t *const data,
                                         size_t data_byte_len);

CRYPTO_FUNCTION int32_t sha512_finish_soft(sha512_ctx_t *const ctx,
                                           uint8_t *const hash,
                                           size_t *const hash_len);

CRYPTO_FUNCTION void sha512_append_bit_len(uint8_t *const buffer,
                                           uint64_t *const length);

#endif /* _SOFT_SHA512_H */
