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
 * @file soft_ecdh.h
 * @brief software Elliptic Curve Diffie-Hellman algorithm implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_BACKEND_SOFT_ECDH_H
#define SCL_BACKEND_SOFT_ECDH_H

#include <stddef.h>
#include <stdint.h>

#include <crypto_cfg.h>

#include <backend/api/asymmetric/ecc/ecc.h>
#include <backend/api/asymmetric/ecc/ecdh.h>
#include <backend/api/scl_backend_api.h>

/**
 * @addtogroup SOFTWARE
 * @addtogroup SOFT_ECDH
 * @ingroup SOFTWARE
 *  @{
 */

/**
 * @brief compute shared secret with ECDH
 *
 * @param[in] scl                   metal scl context
 * @param[in] curve_params          ECC curve parameters (use @ref
 * ecc_secp256r1,
 *          @ref ecc_secp384r1, @ref ecc_secp521r1, or custom curves)
 * @param[in] priv_key              private key
 * @param[in] pub_key               peer public key
 * @param[out] shared_secret        shared secret buffer
 * @param[in,out] shared_secret_len output buffer length/ shared_secret length
 * @return 0 in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
CRYPTO_FUNCTION int32_t
soft_ecdh(const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
          const uint8_t *const priv_key,
          const ecc_affine_const_point_t *const peer_pub_key,
          uint8_t *const shared_secret, size_t *const shared_secret_len);

/** @}*/

#endif /* SCL_BACKEND_SOFT_ECDH_H */
