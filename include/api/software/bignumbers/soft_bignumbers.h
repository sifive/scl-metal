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
#include <api/scl_api.h>

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
 * @brief big integer compare
 *
 * @param[in] a             first array to compare
 * @param[in] b             second array to compare
 * @param[in] word_size     number of 64 bits words to compare
 * @return 0            a == b
 * @return 1            a > b
 * @return -1           a < b
 * @warning No check on pointer value
 */
CRYPTO_FUNCTION int32_t soft_bignum_compare(const uint64_t *const a,
                                            const uint64_t *const b,
                                            size_t word_size);

/**
 * @brief Increment big number by one
 *
 * @param[in,out] array             Input array a
 * @param[in] nb_32b_words          number of 32 bits words to use in calcul
 * @return  the carry from the addition
 * @warning Warning the big number need to be little endian convert if necessary
 * @warning nb_32b_words is limited to 0x3FFFFFFF
 */
CRYPTO_FUNCTION uint64_t soft_bignum_inc(uint64_t *const array,
                                         size_t nb_32b_words);

/**
 * @brief Do big number addition
 *
 * @param[in] in_a              Input array a
 * @param[in] in_b              Input array b
 * @param[out] out              Output array (addition result)
 * @param[in] nb_32b_words      number of 32 bits words to use in calcul
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
 * @param[in] in_a              Input array a
 * @param[in] in_b              Input array b
 * @param[out] out              Output array (substration result)
 * @param[in] nb_32b_words      number of 32 bits words to use in calcul
 * @return  the carry from the substraction
 * @warning Warning the big number need to be little endian convert if necessary
 * @warning nb_32b_words is limited to 0x3FFFFFFF
 * @warning bignumber in input are considered unsigned
 * @warning carry is set when in_a < in_b (in case a positive number is
 * intended, you can do a bitwise not)
 */
CRYPTO_FUNCTION uint64_t soft_bignum_sub(const uint64_t *const in_a,
                                         const uint64_t *const in_b,
                                         uint64_t *const out,
                                         size_t nb_32b_words);

/**
 * @brief Big integer multiplication
 *
 * @param[in] in_a          Input array a
 * @param[in] in_b          Input array a
 * @param[out] out          Output array, should be twice the size of input
 * array
 * @param[in] nb_32b_words  Number of words, of inputs arrays
 * @warning Output should be 2 time the size of Inputs arrays
 */
CRYPTO_FUNCTION void soft_bignum_mult(const uint64_t *const in_a,
                                      const uint64_t *const in_b,
                                      uint64_t *const out, size_t nb_32b_words);

/**
 * @brief bignumber left shift
 *
 * @param[in] scl           metal scl context (not used in case of soft sha)
 * @param[in] in            big integer array to left shift
 * @param[out] out          output big integer
 * @param[in] shift         number of bits to left shift
 * @param[in] nb_32b_words  size of the big integer in 32bits words
 * @return 0 success
 * @return != 0 otherwise @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_bignum_leftshift(const metal_scl_t *const scl,
                                              const uint64_t *const in,
                                              uint64_t *const out, size_t shift,
                                              size_t nb_32b_words);

/**
 * @brief bignumber right shift
 *
 * @param[in] scl           metal scl context (not used in case of soft sha)
 * @param[in] in            big integer array to right shift
 * @param[out] out          output big integer
 * @param[in] shift         number of bits to right shift
 * @param[in] nb_32b_words  size of the big integer in 32bits words
 * @return 0 success
 * @return != 0 otherwise @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_bignum_rightshift(const metal_scl_t *const scl,
                                               const uint64_t *const in,
                                               uint64_t *const out,
                                               size_t shift,
                                               size_t nb_32b_words);

#endif /* _SOFT_BIGNUMBERS_H */