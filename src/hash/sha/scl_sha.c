/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * Copyright 2020 SiFive, Inc
 * SPDX-License-Identifier: MIT
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
 * @file scl_sha.c
 * @brief implementation of the hash generic interface taking the hash function
 * algo reference as a parameter
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: Apache-2.0
 *
 */

#include <scl/scl_retdefs.h>
#include <scl/scl_sha.h>

#include <api/scl_api.h>

#include <api/scl_api.h>

extern metal_scl_t *scl_ctx;

int32_t scl_sha(scl_hash_mode_t algo, const uint8_t *const data,
                size_t data_len, uint8_t *const hash,
                size_t *const hash_len)
{
    int32_t result;
    scl_sha_ctx_t ctx;

    result = scl_ctx->hash_func.sha_init(scl_ctx, &ctx, algo, SCL_BIG_ENDIAN_MODE);
    if( SCL_OK != result) {
        return(result);
    }

    result = scl_ctx->hash_func.sha_core(scl_ctx, &ctx, data, data_len);
    if( SCL_OK != result) {
        return(result);
    }

    result = scl_ctx->hash_func.sha_finish(scl_ctx, &ctx, hash, hash_len);
    if( SCL_OK != result) {
        return(result);
    }
}

int32_t scl_sha_init(scl_sha_ctx_t *const ctx, scl_hash_mode_t algo)
{
    if(NULL == ctx) {
        return(SCL_INVALID_INPUT);
    }

    return (
        scl_ctx->hash_func.sha_init(scl_ctx, ctx, algo, SCL_BIG_ENDIAN_MODE));
}

int32_t scl_sha_core(scl_sha_ctx_t *const ctx, const uint8_t *const data,
                     size_t data_len)
{
    if(NULL == ctx) {
        return(SCL_INVALID_INPUT);
    }

    return (scl_ctx->hash_func.sha_core(scl_ctx, ctx, data, data_len));
}

int32_t scl_sha_finish(scl_sha_ctx_t *const ctx, uint8_t *const hash,
                       size_t *const hash_len)
{
    if(NULL == ctx) {
        return(SCL_INVALID_INPUT);
    }

    return (scl_ctx->hash_func.sha_finish(scl_ctx, ctx, hash, hash_len));
}

/**
 * this function is used to determine if a proposed integer is a valide hash
 * digest length it is used in ECDSA for checking
 */
int32_t scl_valid_hash_digest_length(size_t inputlength)
{
    if (inputlength != SHA256_BYTE_HASHSIZE)
        if (inputlength != SHA384_BYTE_HASHSIZE)
            if (inputlength != SHA512_BYTE_HASHSIZE)
                return (SCL_INVALID_INPUT);
    return (SCL_OK);
}
