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
 * @file soft_ecdsa.h
 * @brief software elliptic curve digital signature algorithm implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_BACKEND_SOFT_ECDSA_H
#define SCL_BACKEND_SOFT_ECDSA_H

#include <stddef.h>
#include <stdint.h>

#include <crypto_cfg.h>

#include <backend/api/asymmetric/ecc/ecc.h>
#include <backend/api/asymmetric/ecc/ecdsa.h>
#include <backend/api/scl_backend_api.h>

/**
 * @addtogroup COMMON
 * @addtogroup ECC
 * @ingroup COMMON
 *  @{
 */

/**
 * @brief ECDSA signature
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params  ECC curve parameters (use @ref ecc_secp256r1,
 *          @ref ecc_secp384r1, @ref ecc_secp521r1, or custom curves)
 * @param[in] priv_key      private key
 * @param[out] signature    signature structure that will hold results
 * @param[in] hash          hash value to sign
 * @param[in] hash_len      hash value length
 * @return 0 in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 * @note Private key shall be big endian
 * @note Signature elements will be big endian
 * @note Hash value shall be big endian
 * @note In case of doubt on the endianess of elements, big endian is the
 * natural representation for such elements, this is what you will find in
 * literature
 * @note private key shall be curve_params->curve_bsize
 * @note signature elements buffer shall be at least curve_params->curve_bsize
 * long
 * @warning For security purpose, the hash length should be equal to superior to
 * curve_params->curve_bsize. Otherwise, the strength of the signature is reduce
 * to the lowest strength between the hash or the signature.
 */
CRYPTO_FUNCTION int32_t soft_ecdsa_signature(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const uint8_t *const priv_key, const ecdsa_signature_t *const signature,
    const uint8_t *const hash, size_t hash_len);

/**
 * @brief ECDSA signature verification
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params  ECC curve parameters (use @ref ecc_secp256r1,
 *          @ref ecc_secp384r1, @ref ecc_secp521r1, or custom curves)
 * @param[in] pub_key       public key
 * @param[in] signature     signature to check
 * @param[in] hash          hash value on which the signature has been performed
 * @param[in] hash_len      hash value length
 * @return 0 in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 * @note Public key elements shall be big endian
 * @note Signature elements shall be big endian
 * @note Hash value shall be big endian
 * @note In case of doubt on the endianess of elements, big endian is the
 * natural representation for such elements, this is what you will find in
 * literature
 * @note public key shall be curve_params->curve_bsize
 * @note signature elements shall be at least curve_params->curve_bsize
 * long
 * @warning For security purpose, the hash length should be equal to superior to
 * curve_params->curve_bsize. Otherwise, the strength of the signature is reduce
 * to the lowest strength between the hash or the signature.
 */
CRYPTO_FUNCTION int32_t soft_ecdsa_verification(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_affine_const_point_t *const pub_key,
    const ecdsa_signature_const_t *const signature, const uint8_t *const hash,
    size_t hash_len);

/** @}*/

#endif /* SCL_BACKEND_SOFT_ECDSA_H */
