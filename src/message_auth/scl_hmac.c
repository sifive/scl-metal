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
 * @file scl_hmac.c
 * @brief implementation of the hmac generic interface taking the hash function
 * algo reference as a parameter
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <scl/scl_retdefs.h>

#include <scl/scl_hmac.h>

#include <backend/api/scl_backend_api.h>

int32_t scl_hmac_init(const metal_scl_t *const scl_ctx,
                      scl_hmac_ctx_t *const hmac_ctx,
                      scl_sha_ctx_t *const sha_ctx, scl_hash_mode_t hash_mode,
                      const uint8_t *const key, size_t key_len)
{
    if (NULL == scl_ctx)
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl_ctx->hmac_func.init))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (scl_ctx->hmac_func.init(scl_ctx, hmac_ctx, sha_ctx, hash_mode, key,
                                    key_len));
}

int32_t scl_hmac_core(const metal_scl_t *const scl_ctx,
                      scl_hmac_ctx_t *const hmac_ctx, const uint8_t *const data,
                      size_t data_len)
{
    if (NULL == scl_ctx)
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl_ctx->hmac_func.init))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (scl_ctx->hmac_func.core(scl_ctx, hmac_ctx, data, data_len));
}

int32_t scl_hmac_finish(const metal_scl_t *const scl_ctx,
                        scl_hmac_ctx_t *const hmac_ctx, uint8_t *const mac,
                        size_t *const mac_len)
{
    if (NULL == scl_ctx)
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl_ctx->hmac_func.init))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (scl_ctx->hmac_func.finish(scl_ctx, hmac_ctx, mac, mac_len));
}
