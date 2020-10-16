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
 * @file soft_hmac.c
 * @brief software hmac implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <backend/software/message_auth/soft_hmac.h>

/*! @brief ipad padding byte */
#define SOFT_HMAC_IPAD_BYTE ((uint8_t)0x36)

/*! @brief opad padding byte */
#define SOFT_HMAC_OPAD_BYTE ((uint8_t)0x5C)

static int32_t soft_hmac_block_size(hash_mode_t hash_mode);

static int32_t soft_hmac_block_size(hash_mode_t hash_mode)
{
    int32_t blocksize;

    switch (hash_mode)
    {
    case SCL_HASH_SHA224:
    case SCL_HASH_SHA256:
        blocksize = SHA256_BYTE_BLOCKSIZE;
        break;
    case SCL_HASH_SHA384:
    case SCL_HASH_SHA512:
        blocksize = SHA512_BYTE_BLOCKSIZE;
        break;
    default:
        return (SCL_INVALID_INPUT);
    }

    return (blocksize);
}

int32_t soft_hmac_init(const metal_scl_t *const scl, hmac_ctx_t *const hmac_ctx,
                       sha_ctx_t *const sha_ctx, hash_mode_t hash_mode,
                       const uint8_t *const key, size_t key_len)
{
    int32_t result;
    size_t blocksize;
    size_t hashsize;
    size_t i;

    if ((NULL == scl) || (NULL == hmac_ctx) || (NULL == sha_ctx) ||
        (NULL == key))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->hash_func.sha_init) ||
        (NULL == scl->hash_func.sha_core) ||
        (NULL == scl->hash_func.sha_finish))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    result = soft_hmac_block_size(hash_mode);
    if (0 > result)
    {
        return (result);
    }
    else
    {
        blocksize = (size_t)result;
    }

    /* step 1 */
    if (key_len == blocksize)
    {
        memcpy(hmac_ctx->k0, key, blocksize);
    }
    /* step 2 */
    else if (key_len > blocksize)
    {
        result = scl->hash_func.sha_init(scl, sha_ctx, hash_mode,
                                         SCL_BIG_ENDIAN_MODE);
        if (SCL_OK != result)
        {
            return (result);
        }

        result = scl->hash_func.sha_core(scl, sha_ctx, key, key_len);
        if (SCL_OK != result)
        {
            return (result);
        }

        hashsize = sizeof(hmac_ctx->k0);
        result =
            scl->hash_func.sha_finish(scl, sha_ctx, hmac_ctx->k0, &hashsize);
        if (SCL_OK != result)
        {
            return (result);
        }

        memset(&hmac_ctx->k0[hashsize], 0, blocksize - hashsize);
    }
    /* step 3 */
    else
    {
        memcpy(hmac_ctx->k0, key, key_len);
        memset(&hmac_ctx->k0[key_len], 0, blocksize - key_len);
    }

    /* step 4 */
    for (i = 0; i < blocksize; i++)
    {
        hmac_ctx->k0[i] ^= SOFT_HMAC_IPAD_BYTE;
    }

    /* part of steps 5 & 6, the sha_core will ensure the concatenation */
    result =
        scl->hash_func.sha_init(scl, sha_ctx, hash_mode, SCL_BIG_ENDIAN_MODE);
    if (SCL_OK != result)
    {
        return (result);
    }

    result = scl->hash_func.sha_core(scl, sha_ctx, hmac_ctx->k0, blocksize);
    if (SCL_OK != result)
    {
        return (result);
    }

    /* undo step 4 for steps 7, 8, 9 */
    for (i = 0; i < blocksize; i++)
    {
        hmac_ctx->k0[i] ^= SOFT_HMAC_IPAD_BYTE;
    }

    hmac_ctx->sha_ctx = sha_ctx;
    hmac_ctx->hash_mode = hash_mode;

    return (SCL_OK);
}

int32_t soft_hmac_core(const metal_scl_t *const scl, hmac_ctx_t *const hmac_ctx,
                       const uint8_t *const data, size_t data_len)
{
    int32_t result;

    if ((NULL == scl) || (NULL == hmac_ctx) || (NULL == data) ||
        (NULL == hmac_ctx->sha_ctx))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->hash_func.sha_core))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    /* step 6 */
    result = scl->hash_func.sha_core(scl, hmac_ctx->sha_ctx, data, data_len);
    if (SCL_OK != result)
    {
        return (result);
    }

    return (SCL_OK);
}

int32_t soft_hmac_finish(const metal_scl_t *const scl,
                         hmac_ctx_t *const hmac_ctx, uint8_t *const mac,
                         size_t *const mac_len)
{
    int32_t result;
    size_t blocksize;
    size_t hashsize;
    size_t i;

    if ((NULL == scl) || (NULL == hmac_ctx) || (NULL == hmac_ctx->sha_ctx) ||
        (NULL == mac) || (NULL == mac_len))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->hash_func.sha_init) ||
        (NULL == scl->hash_func.sha_core) ||
        (NULL == scl->hash_func.sha_finish))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    result = soft_hmac_block_size(hmac_ctx->hash_mode);
    if (0 > result)
    {
        return (result);
    }
    else
    {
        blocksize = (size_t)result;
    }

    /* finish step 6 */
    hashsize = *mac_len;
    result = scl->hash_func.sha_finish(scl, hmac_ctx->sha_ctx, mac, &hashsize);
    if (SCL_OK != result)
    {
        return (result);
    }

    /* step 7 */
    for (i = 0; i < blocksize; i++)
    {
        hmac_ctx->k0[i] ^= SOFT_HMAC_OPAD_BYTE;
    }

    /* steps 8 and 9 */
    result = scl->hash_func.sha_init(scl, hmac_ctx->sha_ctx,
                                     hmac_ctx->hash_mode, SCL_BIG_ENDIAN_MODE);
    if (SCL_OK != result)
    {
        return (result);
    }

    result = scl->hash_func.sha_core(scl, hmac_ctx->sha_ctx, hmac_ctx->k0,
                                     blocksize);
    if (SCL_OK != result)
    {
        return (result);
    }

    result = scl->hash_func.sha_core(scl, hmac_ctx->sha_ctx, mac, hashsize);
    if (SCL_OK != result)
    {
        return (result);
    }

    result = scl->hash_func.sha_finish(scl, hmac_ctx->sha_ctx, mac, mac_len);
    if (SCL_OK != result)
    {
        return (result);
    }

    /* clear context */
    memset(hmac_ctx, 0, sizeof(hmac_ctx_t));

    return (SCL_OK);
}
