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

#ifndef SCL_BACKEND_SOFT_ECC_KEYGEN_H
#define SCL_BACKEND_SOFT_ECC_KEYGEN_H

#include <crypto_cfg.h>
#include <stddef.h>
#include <stdint.h>

#include <backend/api/asymmetric/ecc/ecc.h>
#include <backend/api/scl_backend_api.h>

/**
 * @addtogroup COMMON
 * @addtogroup ECC
 * @ingroup COMMON
 *  @{
 */

/**
 * @brief checking an affine point is on the provided curve
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params  ECC curve parameters (use @ref ecc_secp256r1,
 *          @ref ecc_secp384r1, @ref ecc_secp521r1, or custom curves)
 * @param[in]  point        Affine point to check
 * @return 0 in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_point_on_curve(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_affine_const_point_t *const point);

/**
 * @brief compute public key from private key and curve parameters
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params  ECC curve parameters (use @ref ecc_secp256r1,
 *          @ref ecc_secp384r1, @ref ecc_secp521r1, or custom curves)
 * @param[in] priv_key              private key
 * @param[out] pub_key              public key
 * @return 0 in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_pubkey_generation(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const uint8_t *const priv_key, ecc_affine_point_t *const pub_key);

/**
 * @brief generate a new ECC keypair
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params  ECC curve parameters (use @ref ecc_secp256r1,
 *          @ref ecc_secp384r1, @ref ecc_secp521r1, or custom curves)
 * @param[out] priv_key         private key
 * @param[out] pub_key          public key
 * @return 0 in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t soft_ecc_keypair_generation(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    uint8_t *const priv_key, ecc_affine_point_t *const pub_key);

/** @}*/

#endif /* SCL_BACKEND_SOFT_ECC_KEYGEN_H */
