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

#include <scl_cfg.h>

#include <scl/scl_aes_ecb.h>
#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

extern metal_scl_t *scl_ctx;
// usual structure: init+core

int scl_aes_ecb_init(uint8_t *key, int key_byte_len, int mode)
{
    int ret;

    SCL_DATA uint64_t key_formated[4] = {0};

    ret = scl_format_key(key, key_byte_len, &key_formated);

    if (SCL_OK != ret)
        return ret;

    scl_ctx->aes_func.setkey(scl_ctx, SCL_AES_KEY128, key_formated);

    // FIXME:
    // key_formated should be secure erased
    return (SCL_OK);
}

// for any input length, multiple of blocks
int scl_aes_ecb_core(uint8_t *dst, uint8_t *src, int src_byte_len, int mode)
{
    int i;
    int ret;

    if (NULL == dst)
        return (SCL_INVALID_OUTPUT);
    if (NULL == src)
        return (SCL_INVALID_INPUT);

    if (src_byte_len & 0xF)
        return (SCL_INVALID_INPUT);

    if (SCL_CIPHER_ENCRYPT == mode)
        for (i = 0; i < src_byte_len; i += SCL_AES_BYTE_BLOCKSIZE)
        {
            ret = scl_aes_encrypt(&(dst[i]), &(src[i]));
        }
    else if (SCL_CIPHER_DECRYPT == mode)
        for (i = 0; i < src_byte_len; i += SCL_AES_BYTE_BLOCKSIZE)
        {
            ret = scl_aes_decrypt(&(dst[i]), &(src[i]));
        }
    return (ret);
}

int scl_aes_ecb(uint8_t *dst, uint8_t *src, int src_byte_len, uint8_t *key,
                int key_byte_len, int mode)
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
    if ((src_byte_len % SCL_AES_BYTE_BLOCKSIZE) != 0)
    {
        return (SCL_INVALID_INPUT);
    }
    if (SCL_CIPHER_DECRYPT != mode && SCL_CIPHER_ENCRYPT != mode)
    {
        return (SCL_INVALID_MODE);
    }
    if ((SCL_AES_BYTE_KEYLEN_128 != key_byte_len) &&
        (SCL_AES_BYTE_KEYLEN_192 != key_byte_len) &&
        (SCL_AES_BYTE_KEYLEN_256 != key_byte_len))
    {
        return (SCL_INVALID_INPUT);
    }
    ret = scl_aes_ecb_init(key, key_byte_len, mode);
    if (SCL_OK != ret)
    {
        return (ret);
    }
    ret = scl_aes_ecb_core(dst, src, src_byte_len, mode);
    // fault testing
    if (SCL_OK != ret)
    {
        return (ret);
    }
    return (SCL_OK);
}