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

#include <api/asymmetric/ecc/ecc.h>
#include <api/asymmetric/ecc/ecdsa.h>
#include <api/scl_api.h>

int32_t soft_ecdsa_signature(const metal_scl_t *const scl,
                             const ecc_curve_t *const curve_params,
                             const uint8_t *const priv_key,
                             ecc_signature_t *const signature,
                             const uint8_t *const hash, size_t hash_len);

int32_t soft_ecdsa_verification(const metal_scl_t *const scl,
                                const ecc_affine_point_t *const pub_key,
                                const ecc_signature_t *const signature,
                                const uint8_t *const hash, size_t hash_len,
                                const ecc_curve_t *const curve_params);

#endif /* SCL_BACKEND_SOFT_ECDSA_H */
