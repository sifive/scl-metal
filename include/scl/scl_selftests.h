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
 * @file scl_selftests.h
 * @brief self tests for sha2 and ecdsa
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_SELFTESTS_H
#define SCL_SELFTESTS_H

#include <stdint.h>

#include <backend/api/scl_backend_api.h>

/**
 * @addtogroup SCL
 * @addtogroup SCL_SELF_TESTS
 * @ingroup SCL
 *  @{
 */

/**
 * @brief test ecdsa secp256r1 with precomputed sha256 hash
 * 
 * @param[in] scl           metal scl context
 * @return O in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
int32_t scl_ecdsa_p256r1_sha256_selftest(const metal_scl_t *const scl);

/**
 * @brief test ecdsa secp384r1 with precomputed sha384 hash
 * 
 * @param[in] scl           metal scl context
 * @return O in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
int32_t scl_ecdsa_p384r1_sha384_selftest(const metal_scl_t *const scl);

/**
 * @brief test ecdsa secp521r1 with precomputed sha512 hash
 * 
 * @param[in] scl           metal scl context
 * @return O in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
int32_t scl_ecdsa_p521r1_sha512_selftest(const metal_scl_t *const scl);

/**
 * @brief test sha256 hash
 * 
 * @param[in] scl           metal scl context
 * @return O in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
int32_t scl_hash_sha256_selftest(const metal_scl_t *const scl);

/**
 * @brief test sha384 hash
 * 
 * @param[in] scl           metal scl context
 * @return O in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
int32_t scl_hash_sha384_selftest(const metal_scl_t *const scl);

/**
 * @brief test sha512 hash
 * 
 * @param[in] scl           metal scl context
 * @return O in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
int32_t scl_hash_sha512_selftest(const metal_scl_t *const scl);

/** @}*/

#endif /* SCL_SELFTESTS_H */
