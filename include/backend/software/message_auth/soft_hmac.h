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
 * @file soft_hmac.h
 * @brief software HMAC implementation 
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_BACKEND_SOFT_HMAC_H
#define SCL_BACKEND_SOFT_HMAC_H

#include <crypto_cfg.h>
#include <stddef.h>
#include <stdint.h>

#include <backend/api/message_auth/hmac.h>
#include <backend/api/scl_backend_api.h>

/**
 * @addtogroup SOFTWARE
 * @addtogroup SOFT_HMAC
 * @ingroup SOFTWARE
 *  @{
 */

/**
 * @brief Initialize HMAC computation
 *
 * @param[in] scl_ctx           scl context
 * @param[in/out] hmac_ctx      hmac context
 * @param[in/out] sha_ctx       sha context (this will be referenced into hmac
 * context)
 * @param[in] hash_mode         hash mode to use
 * @param[in] key               Key to use for HMAC computation
 * @param[in] key_len           Key length (in byte)
 * @return 0    in case of SUCCESS
 * @return != 0 in case of errors @ref scl_errors_t
 * @warning Do not override sha_ctx before calling soft_hmac_finish()
 */
int32_t soft_hmac_init(const metal_scl_t *const scl, hmac_ctx_t *const hmac_ctx,
                       sha_ctx_t *const sha_ctx, hash_mode_t hash_mode,
                       const uint8_t *const key, size_t key_len);

/**
 * @brief Compute a chunk of data
 *
 * @param[in] scl_ctx           scl context
 * @param[in/out] hmac_ctx      hmac context
 * @param[in] data              data chunk to process
 * @param[in] data_len          data chunk length
 * @return 0    in case of SUCCESS
 * @return != 0 in case of errors @ref scl_errors_t
 * @note Can be called several time
 * @warning Do not override sha_ctx before calling soft_hmac_finish()
 */
int32_t soft_hmac_core(const metal_scl_t *const scl, hmac_ctx_t *const hmac_ctx,
                       const uint8_t *const data, size_t data_len);

/**
 * @brief Finish HMAC computation
 *
 * @param[in] scl_ctx           scl context
 * @param[in/out] hmac_ctx      hmac context
 * @param[in] mac               HMAC computation result
 * @param[in/out] mac_len       HMAC buffer length (in byte)/HMAC length (in
 * byte)
 * @return 0    in case of SUCCESS
 * @return != 0 in case of errors @ref scl_errors_t
 * @warning Do not override sha_ctx before calling soft_hmac_finish()
 */
int32_t soft_hmac_finish(const metal_scl_t *const scl,
                         hmac_ctx_t *const hmac_ctx, uint8_t *const mac,
                         size_t *const mac_len);

/** @}*/

#endif /* SCL_BACKEND_SOFT_HMAC_H */
