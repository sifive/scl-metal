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
 * @file scl_kdf.h
 * @brief defines the generic key derivation function interface, where the hash
 * function is transmitted as a parameter.
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_KDF_H
#define SCL_KDF_H

#include <stddef.h>
#include <stdint.h>

#include <scl_cfg.h>

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

#include <backend/api/key_derivation_functions/kdf.h>
#include <backend/api/scl_backend_api.h>

#include <scl/scl_sha.h>

/**
 * @addtogroup SCL
 * @addtogroup SCL_KDF
 * @ingroup SCL
 *  @{
 */

/**
 * @brief SCL KDF x9.63 context definition
 * @see x963kdf_ctx_t
 */
typedef x963kdf_ctx_t scl_x963kdf_ctx_t;

/**
 * @brief Initiate kdf x9.63 context
 *
 * @param[in] scl_ctx           metal scl context
 * @param[in,out] x963kdf_ctx   key derivation function context
 * @param[in,out] sha_ctx       sha context (this will be referenced into kdf
 * context)
 * @param[in] hash_mode         hash mode
 * @param[in] info              shared information
 * @param[in] info_len          shared information length
 * @return 0                    SUCCESS
 * @return != 0                 otherwise @ref scl_errors_t
 * @warning Do not override sha_ctx before calling soft_kdf_x963_derive()
 */
SCL_FUNCTION int32_t scl_kdf_x963_init(const metal_scl_t *const scl_ctx,
                                       scl_x963kdf_ctx_t *const x963kdf_ctx,
                                       scl_sha_ctx_t *const sha_ctx,
                                       scl_hash_mode_t hash_mode,
                                       const uint8_t *const info,
                                       size_t info_len);

/**
 * @brief derive key based on kdf x9.63 algorithm
 *
 * @param[in] scl_ctx               metal scl context
 * @param[in,out] x963kdf_ctx       key derivation function context
 * @param[in] input_key             input key material
 * @param[in] input_key_len         input key material length
 * @param[out] derivated_key        derived key
 * @param[in] derivated_key_length  derived key length
 * @return 0                        SUCCESS
 * @return != 0                     otherwise @ref scl_errors_t
 */
SCL_FUNCTION int32_t scl_kdf_x963_derive(const metal_scl_t *const scl_ctx,
                                         scl_x963kdf_ctx_t *const x963kdf_ctx,
                                         const uint8_t *const input_key,
                                         size_t input_key_len,
                                         uint8_t *const derivated_key,
                                         size_t derivated_key_length);

/** @}*/

#endif /* SCL_KDF_H */
