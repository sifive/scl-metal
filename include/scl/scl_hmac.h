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
 * @file scl_hmac.h
 * @brief defines the generic HMAC function interface, where the hash function
 * is transmitted as a parameter.
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_HMAC_H
#define SCL_HMAC_H

#include <stddef.h>
#include <stdint.h>

#include <scl_cfg.h>

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

#include <backend/api/asymmetric/ecc/ecc.h>
#include <backend/api/asymmetric/ecc/ecdh.h>
#include <backend/api/scl_backend_api.h>

#include <scl/scl_sha.h>

/**
 * @addtogroup SCL
 * @addtogroup SCL_HMAC
 * @ingroup SCL
 *  @{
 */

/**
 * @brief SCL HMAC context definition
 * @see hmac_ctx_t
 */
typedef hmac_ctx_t scl_hmac_ctx_t;

/**
 * @brief Initialize HMAC computation
 *
 * @param[in] scl_ctx           scl context
 * @param[in,out] hmac_ctx      hmac context
 * @param[in,out] sha_ctx       sha context (this will be referenced into hmac
 * context)
 * @param[in] hash_mode         hash mode to use
 * @param[in] key               Key to use for HMAC computation
 * @param[in] key_len           Key length (in byte)
 * @return 0    in case of SUCCESS
 * @return != 0 in case of errors @ref scl_errors_t
 * @warning Do not override sha_ctx before calling soft_hmac_finish()
 */
SCL_FUNCTION int32_t scl_hmac_init(const metal_scl_t *const scl_ctx,
                                   scl_hmac_ctx_t *const hmac_ctx,
                                   scl_sha_ctx_t *const sha_ctx,
                                   scl_hash_mode_t hash_mode,
                                   const uint8_t *const key, size_t key_len);

/**
 * @brief Compute a chunk of data
 *
 * @param[in] scl_ctx           scl context
 * @param[in,out] hmac_ctx      hmac context
 * @param[in] data              data chunk to process
 * @param[in] data_len          data chunk length
 * @return 0    in case of SUCCESS
 * @return != 0 in case of errors @ref scl_errors_t
 * @note Can be called several time
 * @warning Do not override sha_ctx before calling soft_hmac_finish()
 */
SCL_FUNCTION int32_t scl_hmac_core(const metal_scl_t *const scl_ctx,
                                   scl_hmac_ctx_t *const hmac_ctx,
                                   const uint8_t *const data, size_t data_len);

/**
 * @brief Finish HMAC computation
 *
 * @param[in] scl_ctx           scl context
 * @param[in,out] hmac_ctx      hmac context
 * @param[in] mac               HMAC computation result
 * @param[in,out] mac_len       HMAC buffer length (in byte)/HMAC length (in
 * byte)
 * @return 0    in case of SUCCESS
 * @return != 0 in case of errors @ref scl_errors_t
 * @warning Do not override sha_ctx before calling soft_hmac_finish()
 */
SCL_FUNCTION int32_t scl_hmac_finish(const metal_scl_t *const scl_ctx,
                                     scl_hmac_ctx_t *const hmac_ctx,
                                     uint8_t *const mac, size_t *const mac_len);

/** @}*/

#endif /* SCL_HMAC_H */
