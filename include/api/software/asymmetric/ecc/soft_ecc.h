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

/**
 * @brief copy ecc affine point
 * 
 * @param[in] src                   source affine point
 * @param[out] dst                  destination affine point
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
void soft_ecc_affine_copy(const ecc_bignum_affine_point_t *const src,
                          ecc_bignum_affine_point_t *const dst,
                          size_t curve_nb_32b_words);

/**
 * @brief zeroize copy ecc affine point
 * 
 * @param[in,out] point             jacobian point to zeroize
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
void soft_ecc_affine_zeroize(ecc_bignum_affine_point_t *const point,
                              size_t curve_nb_32b_words);

/**
 * @brief copy ecc jacobian point
 * 
 * @param[in] src                   source jacobian point
 * @param[out] dst                  destination jacobian point
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
void soft_ecc_jacobian_copy(const ecc_bignum_jacobian_point_t *const src,
                            ecc_bignum_jacobian_point_t *const dst,
                            size_t curve_nb_32b_words);

/**
 * @brief zeroize ecc jacobian point
 * 
 * @param[in,out] point             jacobian point to zeroize
 * @param[in] curve_nb_32b_words    number of 32 bits words per coordinate
 */
void soft_ecc_affine_zeroize(ecc_bignum_jacobian_point_t *const point,
                              size_t curve_nb_32b_words);

#endif /* SCL_BACKEND_SOFT_ECC_H */
