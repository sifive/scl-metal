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

#include <api/bignumbers/bignumbers.h>

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
 * @brief zeroise bignum struct
 *
 * @param[out] array        bignumber to zeroise
 * @param[in] nb_64b_words  number of 64 bits words to zeroize
 *
 */
CRYPTO_FUNCTION void soft_bignum_zeroise(uint64_t *const array,
                                         size_t nb_64b_words);

/**
 * @brief Do big number ber addition
 *
 * @param in_a              Input array a
 * @param in_b              Input array b
 * @param out               Output array (addition result)
 * @param nb_32b_words      number of 32 bits words to use in calcul
 * @return  the carry from the addition
 * @warning Warning the big number need to be little endian convert if necessary
 * @warning nb_32b_words is limited to 0x3FFFFFFF
 */
CRYPTO_FUNCTION uint64_t soft_bignum_add(const uint64_t *const in_a,
                                         const uint64_t *const in_b,
                                         uint64_t *const out,
                                         size_t nb_32b_words);

/**
 * @brief Do big number ber substraction
 *
 * @param in_a              Input array a
 * @param in_b              Input array b
 * @param out               Output array (substration result)
 * @param nb_32b_words      number of 32 bits words to use in calcul
 * @return  the carry from the substraction
 * @warning Warning the big number need to be little endian convert if necessary
 * @warning nb_32b_words is limited to 0x3FFFFFFF
 * @warning bignumber in input are considered unsigned
 * @warning carry is set when in_a < in_b (in case a positive number is
 * intended, you can do a bitwise not)
 */
CRYPTO_FUNCTION uint32_t soft_bignum_sub(const uint64_t *const in_a,
                                         const uint64_t *const in_b,
                                         uint64_t *const out,
                                         size_t nb_32b_words);

#endif /* _SOFT_BIGNUMBERS_H */