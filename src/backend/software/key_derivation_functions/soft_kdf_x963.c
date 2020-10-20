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
 * @file soft_kdf_x963.c
 * @brief software x9.63 kdf implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <limits.h>
#include <string.h>

#include <backend/software/key_derivation_functions/soft_kdf_x963.h>

#include <backend/api/macro.h>

static int32_t soft_kdf_x963_hash_length(hash_mode_t hash_mode);

static int32_t soft_kdf_x963_hash_length(hash_mode_t hash_mode)
{
    int32_t hashsize;

    switch (hash_mode)
    {
    case SCL_HASH_SHA224:
        hashsize = SHA224_BYTE_HASHSIZE;
        break;
    case SCL_HASH_SHA256:
        hashsize = SHA256_BYTE_HASHSIZE;
        break;
    case SCL_HASH_SHA384:
        hashsize = SHA384_BYTE_HASHSIZE;
        break;
    case SCL_HASH_SHA512:
        hashsize = SHA512_BYTE_HASHSIZE;
        break;
    default:
        return (SCL_INVALID_INPUT);
    }

    return (hashsize);
}

int32_t soft_kdf_x963_init(const metal_scl_t *const scl,
                           x963kdf_ctx_t *const x963kdf_ctx,
                           sha_ctx_t *const sha_ctx, hash_mode_t hash_mode,
                           const uint8_t *const info, size_t info_len)
{
    if ((NULL == scl) || (NULL == x963kdf_ctx) || (NULL == info) ||
        (NULL == sha_ctx))
    {
        return (SCL_INVALID_INPUT);
    }

    x963kdf_ctx->sha_ctx = sha_ctx;
    x963kdf_ctx->hash_mode = hash_mode;
    x963kdf_ctx->shared_info = info;
    x963kdf_ctx->shared_info_len = info_len;

    return (SCL_OK);
}

int32_t soft_kdf_x963_derive(const metal_scl_t *const scl,
                             x963kdf_ctx_t *const x963kdf_ctx,
                             const uint8_t *const input_key,
                             size_t input_key_len, uint8_t *const derivated_key,
                             size_t derivated_key_length)
{
    int32_t result;
    size_t i;
    size_t hashsize;
    size_t chunk_size;
    size_t derivated_key_index;
    size_t remaining_len;

    /**
     * step 3 : Initialized at 0x00000001 big endian, it will be swap at hash
     * computation
     */
    uint32_t counter = 1;

    if ((NULL == scl) || (NULL == input_key) || (NULL == x963kdf_ctx) ||
        (NULL == derivated_key) || (NULL == x963kdf_ctx->shared_info) ||
        (NULL == x963kdf_ctx->sha_ctx))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->hash_func.sha_init) ||
        (NULL == scl->hash_func.sha_core) ||
        (NULL == scl->hash_func.sha_finish))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    if (0 == derivated_key_length)
    {
        return (SCL_INVALID_LENGTH);
    }

    result = soft_kdf_x963_hash_length(x963kdf_ctx->hash_mode);
    if (0 > result)
    {
        return (result);
    }

    hashsize = (size_t)result;

    ASSERT_COMPILE(sizeof(size_t) == (__riscv_xlen / CHAR_BIT));

#if __riscv_xlen > 32
    {
        /**
         * step 1 : Check that |Z| + |SharedInfo| + 4 < hashmaxlen.
         * If |Z| + |SharedInfo| + 4 ¸ hashmaxlen, output “invalid” and stop.
         * hashmaxlen denote the maximum length in octets of messages that can
         * be hashed using Hash function
         * For SHA-2, hashmaxlen is superior to 0xFFFFFFFFUL, but we won't
         * reach the limit
         * This is unreachable if __riscv_xlen == 32, so don't check.
         */
        if (input_key_len + x963kdf_ctx->shared_info_len + sizeof(counter) >
            0xFFFFFFFFUL)
        {
            return (SCL_INVALID_LENGTH);
        }

        /**
         * step 2 : Check that keydatalen < hashlen × (2^32 − 1).
         * If keydatalen ¸ hashlen × (2^32 − 1), output “invalid” and stop.
         * This is unreachable if __riscv_xlen == 32, so don't check.
         */
        if (derivated_key_length >= hashsize * 0xFFFFFFFFUL)
        {
            return (SCL_INVALID_LENGTH);
        }
    }

#endif

    remaining_len = derivated_key_length;
    i = 0;

    /* step 4 : */
    do
    {
        /* step 4.1 : */
        result = scl->hash_func.sha_init(scl, x963kdf_ctx->sha_ctx,
                                         x963kdf_ctx->hash_mode,
                                         SCL_BIG_ENDIAN_MODE);
        if (SCL_OK != result)
        {
            return (result);
        }

        result = scl->hash_func.sha_core(scl, x963kdf_ctx->sha_ctx, input_key,
                                         input_key_len);
        if (SCL_OK != result)
        {
            return (result);
        }

        counter = bswap32(counter);

        result = scl->hash_func.sha_core(scl, x963kdf_ctx->sha_ctx,
                                         (uint8_t *)&counter, sizeof(counter));
        if (SCL_OK != result)
        {
            return (result);
        }

        counter = bswap32(counter);

        result = scl->hash_func.sha_core(scl, x963kdf_ctx->sha_ctx,
                                         x963kdf_ctx->shared_info,
                                         x963kdf_ctx->shared_info_len);
        if (SCL_OK != result)
        {
            return (result);
        }

        derivated_key_index = i * hashsize;
        chunk_size = hashsize;

        if (remaining_len >= hashsize)
        {
            result = scl->hash_func.sha_finish(
                scl, x963kdf_ctx->sha_ctx, &derivated_key[derivated_key_index],
                &chunk_size);
            if (SCL_OK != result)
            {
                return (result);
            }

            remaining_len -= chunk_size;
        }
        else
        {
            uint8_t digest[hashsize];
            result = scl->hash_func.sha_finish(scl, x963kdf_ctx->sha_ctx,
                                               digest, &chunk_size);
            if (SCL_OK != result)
            {
                return (result);
            }

            memcpy(&derivated_key[derivated_key_index], digest, remaining_len);

            remaining_len = 0;
        }

        /* step 4.2 : */
        counter += 1;
        i++;
    } while (0 != remaining_len);

    return (SCL_OK);
}
