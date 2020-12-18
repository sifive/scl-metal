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
 * @file scl_ecdsa.c
 * @brief defines the generic ECDSA function interface, where the hash function
 * is transmitted as a parameter.
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <scl/scl_ecdsa.h>
#include <scl/scl_retdefs.h>
#include <scl/scl_sha.h>

int32_t scl_ecdsa_signature(const metal_scl_t *const scl,
                            const ecc_curve_t *const curve_params,
                            const uint8_t *const priv_key,
                            const ecdsa_signature_t *const signature,
                            const uint8_t *const hash, size_t hash_len)
{
    int32_t result = 0;

    if ((NULL == scl) || (NULL == hash) || (NULL == curve_params))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->ecdsa_func.signature))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    /* Check hash length to avoid error */
    switch (hash_len)
    {
    case SHA256_BYTE_HASHSIZE:
        if ((curve_params->curve_bsize > hash_len))
        {
            return (SCL_ERR_HASH);
        }
        break;
    case SHA384_BYTE_HASHSIZE:
        if ((curve_params->curve_bsize > hash_len))
        {
            return (SCL_ERR_HASH);
        }
        break;

    case SHA512_BYTE_HASHSIZE:
        /* code */
        if ((curve_params->curve_bsize > hash_len) &&
            (ECC_SECP521R1 != curve_params->curve))
        {
            return (SCL_ERR_HASH);
        }
        break;

    default:
        return (SCL_ERR_HASH);
    }

    result = scl->ecdsa_func.signature(scl, curve_params, priv_key, signature,
                                       hash, hash_len);

    return (result);
}

int32_t scl_ecdsa_verification(const metal_scl_t *const scl,
                               const ecc_curve_t *const curve_params,
                               const ecc_affine_const_point_t *const pub_key,
                               const ecdsa_signature_const_t *const signature,
                               const uint8_t *const hash, size_t hash_len)
{
    int32_t result = 0;

    if ((NULL == scl) || (NULL == hash) || (NULL == curve_params))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->ecdsa_func.verification))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    /* Check hash length to avoid error */
    switch (hash_len)
    {
    case SHA256_BYTE_HASHSIZE:
        if ((curve_params->curve_bsize > hash_len))
        {
            return (SCL_ERR_HASH);
        }
        break;
    case SHA384_BYTE_HASHSIZE:
        if ((curve_params->curve_bsize > hash_len))
        {
            return (SCL_ERR_HASH);
        }
        break;

    case SHA512_BYTE_HASHSIZE:
        /* code */
        if ((curve_params->curve_bsize > hash_len) &&
            (ECC_SECP521R1 != curve_params->curve))
        {
            return (SCL_ERR_HASH);
        }
        break;

    default:
        return (SCL_ERR_HASH);
    }

    result = scl->ecdsa_func.verification(scl, curve_params, pub_key, signature,
                                          hash, hash_len);

    return (result);
}
