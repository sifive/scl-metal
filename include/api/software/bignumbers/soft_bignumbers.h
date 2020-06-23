/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
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

/**
 * @file soft_bignumbers.h
 * @brief arithmetic on bignumber, software implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _SOFT_BIGNUMBERS_H
#define _SOFT_BIGNUMBERS_H

#include <crypto_cfg.h>
#include <stddef.h>
#include <stdint.h>

#if __riscv_xlen == 32
#define SCL_WORD_MAX_VALUE 0xFFFFFFFF
#define SCL_WORD_HALF_VALUE 0xFFFF
#define SCL_MAX_DIGITS (SCL_BIGNUMBERS_MAXBYTESIZE / 4 + 1)
#define SCL_WORD_BITS 32
#define SCL_HALFWORD_BITS 16
#define SCL_DOUBLE_WORD_BITS 64
#define SCL_DOUBLE_WORD_BYTES 8
#define SCL_WORD_BYTES 4
#define SCL_BYTE_BITS 8
#elif __riscv_xlen == 64
// #ifdef SCL_WORD64
#define SCL_WORD_MAX_VALUE 0xFFFFFFFF
#define SCL_WORD_HALF_VALUE 0xFFFF
#define SCL_MAX_DIGITS (SCL_BIGNUMBERS_MAXBYTESIZE / 4 + 1)
#define SCL_WORD_BITS 32
#define SCL_HALFWORD_BITS 16
#define SCL_DOUBLE_WORD_BITS 64
#define SCL_WORD_BYTES 4
#define SCL_BYTE_BITS 8
#endif

/**
 * @brief memset for 64 bits word to target to speed up big numbers computation
 *
 * @param[out] array        array to memset
 * @param[in] value         value to set in the array
 * @param[in] word_size     number of 64 bits words to set
 * @warning No check on pointer value
 */
void scl_bignum_memset(uint64_t *const array, uint64_t value, size_t word_size);

/**
 * @brief memcopy for 64 bits word to target to speed up big numbers computation
 *
 * @param[out] dest          destination 64 bits words array
 * @param[in] source        source 64 bits words array
 * @param[in] word_size     number of 64 bits words to copy
 * @warning No check on pointer value
 */
void scl_bignum_memcpy(uint64_t *const dest, const uint64_t *const source,
                       size_t word_size);

/**
 * @brief memcmp for 64 bits word to target to speed up big numbers computation
 *
 * @param[in] a             first array to compare
 * @param[in] b             second array to compare
 * @param[in] word_size     number of 64 bits words to compare
 * @return 0            a == b
 * @return 1            a > b
 * @return -1           a < b
 * @warning No check on pointer value
 */
int32_t scl_bignum_memcmp(const uint64_t *const a, const uint64_t *const b,
                          size_t word_size);

#endif /* _SOFT_BIGNUMBERS_H */