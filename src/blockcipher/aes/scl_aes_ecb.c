/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_aes_ecb.c
 * @brief ECB mode for the AES.
 * AES is NIST FIPS-197, ECB follow NIST SP800-38A
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
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

#if 1
#include <scl_cfg.h>

#include <api/scl_api.h>

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

#include <api/blockcipher/aes/aes.h>

#include <scl/scl_aes_ecb.h>

extern metal_scl_t *scl_ctx;
// usual structure: init+core

int32_t scl_aes_ecb_init(const metal_scl_t *const scl_ctx, uint8_t *key, int key_byte_len, int mode)
{
    int ret;

    if (NULL == scl_ctx)
    {
        return (SCL_INVALID_INPUT);
    }

    uint64_t key_formated[4] = {0};

    ret = scl_format_key(key, key_byte_len, &key_formated);

    if (SCL_OK != ret)
        return ret;

    scl_ctx->aes_func.setkey(scl_ctx, SCL_AES_KEY128, key_formated);

    /* @FIXME: /*
    /* key_formated should be secure erased */

    return (SCL_OK);
}

// for any input length, multiple of blocks
int32_t scl_aes_ecb_core(const metal_scl_t *const scl_ctx, uint8_t *dst, uint8_t *src, int src_byte_len, scl_process_t mode)
{
    int i;
    int ret;

    if (NULL == scl_ctx)
    {
        return (SCL_INVALID_INPUT);
    }

    if (src_byte_len & 0xF)
        return (SCL_INVALID_INPUT);

/*
    if (SCL_CIPHER_ENCRYPT == mode)
        for (i = 0; i < src_byte_len; i += BLOCK128_NB_BYTE)
        {
            ret = scl_aes_encrypt(&(dst[i]), &(src[i]));
        }
    else if (SCL_CIPHER_DECRYPT == mode)
        for (i = 0; i < src_byte_len; i += SCL_AES_BYTE_BLOCKSIZE)
        {
            ret = scl_aes_decrypt(&(dst[i]), &(src[i]));
        }
*/
    scl_ctx->aes_func.cipher(scl_ctx, SCL_AES_ECB, mode, SCL_BIG_ENDIAN_MODE, src_byte_len, src, dst);

    return (ret);
}

int32_t scl_aes_ecb(const metal_scl_t *const scl_ctx, uint8_t *dst, uint8_t *src, int src_byte_len, uint8_t *key,
                int key_byte_len, scl_process_t mode)
{
    int ret;
    if (NULL == src || NULL == key)
    {
        return (SCL_INVALID_INPUT);
    }
    if (NULL == dst)
    {
        return (SCL_INVALID_OUTPUT);
    }
    if ((src_byte_len % BLOCK128_NB_BYTE) != 0)
    {
        return (SCL_INVALID_INPUT);
    }
    if ((SCL_ENCRYPT != mode) && (SCL_ENCRYPT != mode))
    {
        return (SCL_INVALID_MODE);
    }
    if ((SCL_KEY128 != key_byte_len) &&
        (SCL_KEY192 != key_byte_len) &&
        (SCL_KEY256 != key_byte_len))
    {
        return (SCL_INVALID_INPUT);
    }
    ret = scl_aes_ecb_init(scl_ctx, key, key_byte_len, mode);
    if (SCL_OK != ret)
    {
        return (ret);
    }
    ret = scl_aes_ecb_core(scl_ctx, dst, src, src_byte_len, mode);
    // fault testing
    if (SCL_OK != ret)
    {
        return (ret);
    }
    return (SCL_OK);
}
#endif