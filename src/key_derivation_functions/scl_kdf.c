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
 * @file scl_kdf.c
 * @brief defines the generic key derivation function interface, where the hash
 * function is transmitted as a parameter.
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <scl/scl_retdefs.h>

#include <scl/scl_kdf.h>

#include <backend/api/scl_backend_api.h>

int32_t scl_kdf_x963_init(const metal_scl_t *const scl_ctx,
                          scl_x963kdf_ctx_t *const x963kdf_ctx,
                          scl_sha_ctx_t *const sha_ctx,
                          scl_hash_mode_t hash_mode, const uint8_t *const info,
                          size_t info_len)
{
    if (NULL == scl_ctx)
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl_ctx->kdf_func.x963_init))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (scl_ctx->kdf_func.x963_init(scl_ctx, x963kdf_ctx, sha_ctx,
                                        hash_mode, info, info_len));
}

int32_t scl_kdf_x963_derive(const metal_scl_t *const scl_ctx,
                            scl_x963kdf_ctx_t *const x963kdf_ctx,
                            const uint8_t *const input_key,
                            size_t input_key_len, uint8_t *const derivated_key,
                            size_t derivated_key_length)
{
    if (NULL == scl_ctx)
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl_ctx->kdf_func.x963_derive))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (scl_ctx->kdf_func.x963_derive(scl_ctx, x963kdf_ctx, input_key,
                                          input_key_len, derivated_key,
                                          derivated_key_length));
}
