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
 * FROM, OUT OF OR IN COlNNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 ******************************************************************************/

/**
 * @file soft_ecc.h
 * @brief software elliptic curve cryptography implementation (mostly operation
 * on elliptic curves)
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_BACKEND_SOFT_ECC_H
#define SCL_BACKEND_SOFT_ECC_H

#include <crypto_cfg.h>
#include <stddef.h>
#include <stdint.h>

#include <api/asymmetric/ecc/ecc.h>
#include <api/scl_api.h>

/**
 * @brief copy ecc affine point
 *
 * @param[in] src                   source affine point
 * @param[out] dst                  destination affine point
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
CRYPTO_FUNCTION void
soft_ecc_affine_copy(const ecc_bignum_affine_point_t *const src,
                     ecc_bignum_affine_point_t *const dst,
                     size_t curve_nb_32b_words);

/**
 * @brief zeroize copy ecc affine point
 *
 * @param[in,out] point             jacobian point to zeroize
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
CRYPTO_FUNCTION void
soft_ecc_affine_zeroize(ecc_bignum_affine_point_t *const point,
                        size_t curve_nb_32b_words);

/**
 * @brief copy ecc jacobian point
 *
 * @param[in] src                   source jacobian point
 * @param[out] dst                  destination jacobian point
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
CRYPTO_FUNCTION void
soft_ecc_jacobian_copy(const ecc_bignum_jacobian_point_t *const src,
                       ecc_bignum_jacobian_point_t *const dst,
                       size_t curve_nb_32b_words);

/**
 * @brief zeroize ecc jacobian point
 *
 * @param[in,out] point             jacobian point to zeroize
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
CRYPTO_FUNCTION void
soft_ecc_jacobian_zeroize(ecc_bignum_jacobian_point_t *const point,
                          size_t curve_nb_32b_words);

/**
 * @brief  convert affine coordinate into jacobian coordinates
 *
 * @param[in] scl               metal scl context
 * @param[in] curve_params      elliptic curve parameters
 * @param[in] in                Input affine coordinates
 * @param[out] out              Output jacobian coordinates
 * @param[in] nb_32b_words      number of 32 bits words per coordinate
 * @return = 0 in case of success
 * @return < 0 otherwise @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_convert_affine_to_jacobian(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_point_t *const in,
    ecc_bignum_jacobian_point_t *const out, size_t nb_32b_words);

/**
 * @brief convert jacobian coordinate into affine coordinates
 *
 * @param[in] scl               metal scl context
 * @param[in] curve_params      elliptic curve parameters
 * @param[in] in                Input jacobian coordinates
 * @param[out] out              Output affine coordinates
 * @param[in] nb_32b_words      number of 32 bits words per coordinate
 * @return = 0 in case of success
 * @return < 0 otherwise @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_convert_jacobian_to_affine(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_jacobian_point_t *const in,
    ecc_bignum_affine_point_t *const out, size_t nb_32b_words);

/**
 * @brief check if point is at the infinite
 * @details by definition in the choosen jacobian projection, infinite point is
 * x = 1, y = 1, z = 0
 *
 * @param[in] scl               metal scl context
 * @param[in] point             point jacobian coordinates
 * @param[in] nb_32b_words      number of 32 bits words per coordinate
 * @return true (== 1)  in case the point is at the infinite
 * @return false (== 0) in case the point is not at the infinite
 * @return < 0 otherwise @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_infinite_jacobian(
    const metal_scl_t *const scl,
    const ecc_bignum_jacobian_point_t *const point, size_t nb_32b_words);

/**
 * @brief Add 2 jacobian points
 *
 * @param[in] scl               metal scl context
 * @param[in] curve_params      elliptic curve parameters
 * @param[in] in_a              Input jacobian coordinates
 * @param[in] in_b              Input jacobian coordinates
 * @param[out] out              Output jacobian coordinates
 * @param[in] nb_32b_words      number of 32 bits words per coordinate
 * @return = 0 in case of success
 * @return < 0 otherwise @ref scl_errors_t
 * @note use Mathieu Rivain algorithm 16 (cf: Fast and Regular Algorithms for
 * Scalar Multiplication)
 */
CRYPTO_FUNCTION int32_t soft_ecc_add_jacobian_jacobian(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_jacobian_point_t *const in_a,
    const ecc_bignum_jacobian_point_t *const in_b,
    ecc_bignum_jacobian_point_t *const out, size_t nb_32b_words);

/**
 * @brief Double a jacobian point
 *
 * @param[in] scl               metal scl context
 * @param[in] curve_params      elliptic curve parameters
 * @param[in] in                Input jacobian coordinates
 * @param[out] out              Output jacobian coordinates
 * @param[in] nb_32b_words      number of 32 bits words per coordinate
 * @return = 0 in case of success
 * @return < 0 otherwise @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_double_jacobian(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_jacobian_point_t *const in,
    ecc_bignum_jacobian_point_t *const out, size_t nb_32b_words);

/**
 * @brief extract a bit in a bgnum array
 *
 * @param[in] array         bignum array
 * @param[in] bit_idx       bit index to extract
 * @return 1 or 0 depending if the bit is set or not
 */
size_t soft_ecc_bit_extract(uint32_t *array, size_t bit_idx);

#endif /* SCL_BACKEND_SOFT_ECC_H */