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
 * @addtogroup COMMON
 * @addtogroup ECC
 * @ingroup COMMON
 *  @{
 */

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
    const ecc_bignum_affine_const_point_t *const in,
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
 * @brief Add two affine point
 *
 * @param[in] scl               metal scl context
 * @param[in] curve_params      elliptic curve parameters
 * @param[in] in1               first point
 * @param[in] in2               second point
 * @param[out] out              adition result
 * @param[in] nb_32b_words      Points coordinates number of 32 bits words
 * @return 0 in case of success
 * @return < 0 otherwise @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_add_affine_affine(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_point_t *const in1,
    const ecc_bignum_affine_point_t *const in2,
    ecc_bignum_affine_point_t *const out, size_t nb_32b_words);

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
 * @brief extract a bit in a bignum array
 *
 * @param[in] array         bignum array
 * @param[in] bit_idx       bit index to extract
 * @return 1 or 0 depending if the bit is set or not
 */
CRYPTO_FUNCTION size_t soft_ecc_bit_extract(const uint32_t *const array,
                                            size_t bit_idx);

/**
 * @brief (X,Y)-only co-Zaddition with update - XYCZ-ADD
 * @details Fast and Regular Algorithms for Scalar Multiplication over Elliptic
 * Curves (Rivain) algo 18
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params      ECC curve parameters 
 * @param[in] in1               first input
 * @param[in] in2               second input
 * @param[out] out1             output point conjugate
 * @param[out] out2             first input conjugate (output)
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_xycz_add(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_const_point_t *const in1,
    const ecc_bignum_affine_const_point_t *const in2,
    ecc_bignum_affine_point_t *const out1,
    ecc_bignum_affine_point_t *const out2);

/**
 * @brief (X,Y)-only co-Zconjugate addition - XYCZ-ADDC
 * @details Fast and Regular Algorithms for Scalar Multiplication over Elliptic
 * Curves (Rivain) algo 19
 *
 * @param[in] scl               metal scl context
 * @param[in] curve_params      ECC curve parameters 
 * @param[in] in1               first input
 * @param[in] in2               second input
 * @param[out] out1             output point
 * @param[out] out2             output point conjugate
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_xycz_addc(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_const_point_t *const in1,
    const ecc_bignum_affine_const_point_t *const in2,
    ecc_bignum_affine_point_t *const out1,
    ecc_bignum_affine_point_t *const out2);

/**
 * @brief (X,Y)-only initial doubling with Co-Z Update - XYCZ-IDBL
 * @details Fast and Regular Algorithms for Scalar Multiplication over Elliptic
 * Curves (Rivain) algo 23
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params  ECC curve parameters 
 * @param[in] in            input point
 * @param[out] out1         output point
 * @param[out] out2         output point conjugate
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_xycz_idbl(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_const_point_t *const in,
    ecc_bignum_affine_point_t *const out1,
    ecc_bignum_affine_point_t *const out2);

/**
 * @brief Montgomery ladder with(X,Y)-only co-Zaddition  q = k * point
 * @details Fast and Regular Algorithms for Scalar Multiplication over Elliptic
 * Curves (Rivain) algo 9
 *
 * @param[in] scl               metal scl context
 * @param[in] curve_params      ECC curve parameters 
 * @param[in] point             input point
 * @param[in] k                 scalar to multiply
 * @param[in] k_nb_32bits_words scalar length
 * @param[out] q                output point
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_mult_coz(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_const_point_t *const point, const uint64_t *const k,
    size_t k_nb_32bits_words, ecc_bignum_affine_point_t *const q);

/**
 * Modular Arthmetic optimized for ecc
 */
/**
 * @brief compute modulus p param for curve secp256r1
 * @details perform : remainder = in mod modulus
 *
 * @param[in] scl                   metal scl context
 * @param[in] in                    input big integer (on which the modulus is
 * applied)
 * @param[in] in_nb_32b_words       number of 32 words in input array
 * @param[in] modulus               modulus big integer to apply
 * @param[in] modulus_nb_32b_words  number of 32 words in modulus array
 * @param[out] remainder            remainder array (big integer)
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 * @note remainder should be at least of length equal to modulus_nb_32b_words
 * @warning This function might call @ref soft_bignum_div depending on scl
 * content and therefore have buffer allocation on stack
 */
CRYPTO_FUNCTION int32_t soft_ecc_mod_secp256r1(const metal_scl_t *const scl,
                                               const uint64_t *const in,
                                               size_t in_nb_32b_words,
                                               const uint64_t *const modulus,
                                               size_t modulus_nb_32b_words,
                                               uint64_t *const remainder);

/**
 * @brief compute modulus p param for curve secp381r1
 * @details perform : remainder = in mod modulus
 *
 * @param[in] scl                   metal scl context
 * @param[in] in                    input big integer (on which the modulus is
 * applied)
 * @param[in] in_nb_32b_words       number of 32 words in input array
 * @param[in] modulus               modulus big integer to apply
 * @param[in] modulus_nb_32b_words  number of 32 words in modulus array
 * @param[out] remainder            remainder array (big integer)
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 * @note remainder should be at least of length equal to modulus_nb_32b_words
 * @warning This function might call @ref soft_bignum_div depending on scl
 * content and therefore have buffer allocation on stack
 */
CRYPTO_FUNCTION int32_t soft_ecc_mod_secp384r1(const metal_scl_t *const scl,
                                               const uint64_t *const in,
                                               size_t in_nb_32b_words,
                                               const uint64_t *const modulus,
                                               size_t modulus_nb_32b_words,
                                               uint64_t *const remainder);

/**
 * @brief compute modulus p param for curve secp521r1
 * @details perform : remainder = in mod modulus
 *
 * @param[in] scl                   metal scl context
 * @param[in] in                    input big integer (on which the modulus is
 * applied)
 * @param[in] in_nb_32b_words       number of 32 words in input array
 * @param[in] modulus               modulus big integer to apply
 * @param[in] modulus_nb_32b_words  number of 32 words in modulus array
 * @param[out] remainder            remainder array (big integer)
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 * @note remainder should be at least of length equal to modulus_nb_32b_words
 * @warning This function might call @ref soft_bignum_div depending on scl
 * content and therefore have buffer allocation on stack
 */
CRYPTO_FUNCTION int32_t soft_ecc_mod_secp521r1(const metal_scl_t *const scl,
                                               const uint64_t *const in,
                                               size_t in_nb_32b_words,
                                               const uint64_t *const modulus,
                                               size_t modulus_nb_32b_words,
                                               uint64_t *const remainder);

/**
 * @brief compute modulus with optimizations for standards curves
 * @details perform : remainder = in mod modulus
 *
 * @param[in] scl                   metal scl context
 * @param[in] in                    input big integer (on which the modulus is
 * applied)
 * @param[in] in_nb_32b_words       number of 32 words in input array
 * @param[in] modulus               modulus big integer to apply
 * @param[in] modulus_nb_32b_words  number of 32 words in modulus array
 * @param[out] remainder            remainder array (big integer)
 * @return 0 success
 * @return < 0 in case of errors @ref scl_errors_t
 * @note remainder should be at least of length equal to modulus_nb_32b_words
 * @warning This function might call @ref soft_bignum_div depending on scl
 * content and therefore have buffer allocation on stack
 */
CRYPTO_FUNCTION int32_t soft_ecc_mod(const metal_scl_t *const scl,
                                     const uint64_t *const in,
                                     size_t in_nb_32b_words,
                                     const uint64_t *const modulus,
                                     size_t modulus_nb_32b_words,
                                     uint64_t *const remainder);

/** @}*/

#endif /* SCL_BACKEND_SOFT_ECC_H */
