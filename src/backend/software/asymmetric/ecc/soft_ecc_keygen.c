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
 * @file soft_ecc_keygen.c
 * @brief software elliptic curve key generation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <backend/api/utils.h>

#include <scl/scl_retdefs.h>

#include <backend/api/asymmetric/ecc/ecdsa.h>
#include <backend/software/asymmetric/ecc/soft_ecc.h>
#include <backend/software/asymmetric/ecc/soft_ecc_keygen.h>

/**
 * @brief compute public key from private key and curve parameters
 *
 * @param[in] scl           metal scl context
 * @param[in] curve_params  ECC curve parameters (use @ref ecc_secp256r1,
 *          @ref ecc_secp384r1, @ref ecc_secp521r1, or custom curves)
 * @param[in] priv_key              private key (big integer format)
 * @param[out] pub_key              public key (big integer format)
 * @return 0 in case of success
 * @return > 0 in case of failure @ref scl_errors_t
 */
static int32_t soft_ecc_pubkey_generation_internal(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const uint64_t *const priv_key, ecc_bignum_affine_point_t *const pub_key);

int32_t soft_ecc_point_on_curve_internal(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_const_point_t *const point)
{
    int32_t result = 0;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == point))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->trng_func.get_data) ||
        (NULL == scl->bignum_func.is_null) ||
        (NULL == scl->bignum_func.compare) ||
        (NULL == scl->bignum_func.mod_mult) ||
        (NULL == scl->bignum_func.mod_add) ||
        (NULL == scl->bignum_func.set_modulus))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    {
        uint32_t temp_1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t temp_2[curve_params->curve_wsize] __attribute__((aligned(8)));

        /* Check that point->x and point->y are in the interval [1, p-1] */
        result = scl->bignum_func.compare(scl, point->x, curve_params->p,
                                          curve_params->curve_wsize);
        if (result >= 0)
        {
            return (SCL_ERR_POINT);
        }

        result = scl->bignum_func.compare(scl, point->y, curve_params->p,
                                          curve_params->curve_wsize);
        if (result >= 0)
        {
            return (SCL_ERR_POINT);
        }

        result = scl->bignum_func.is_null(scl, (const uint32_t *)point->x,
                                          curve_params->curve_wsize);
        if (false != result)
        {
            return (SCL_ERR_POINT);
        }

        result = scl->bignum_func.is_null(scl, (const uint32_t *)point->y,
                                          curve_params->curve_wsize);
        if (false != result)
        {
            return (SCL_ERR_POINT);
        }

        /* we check the point match the curve equation : y^2 = a.x + x^3 + b */

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, point->x, point->x,
                                           (uint64_t *)temp_1,
                                           curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, point->x, (uint64_t *)temp_1, (uint64_t *)temp_1,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, point->x,
                                           curve_params->a, (uint64_t *)temp_2,
                                           curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (uint64_t *)temp_1, (uint64_t *)temp_2,
            (uint64_t *)temp_1, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)temp_1,
                                          curve_params->b, (uint64_t *)temp_1,
                                          curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, point->y, point->y,
                                           (uint64_t *)temp_2,
                                           curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.compare(scl, (uint64_t *)temp_1,
                                          (uint64_t *)temp_2,
                                          curve_params->curve_wsize);
        if (0 != result)
        {
            return (SCL_ERR_POINT);
        }
    }

    return (SCL_OK);
}

int32_t soft_ecc_point_on_curve(const metal_scl_t *const scl,
                                const ecc_curve_t *const curve_params,
                                const ecc_affine_const_point_t *const point)
{
    int32_t result = 0;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == point))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == point->x) || (NULL == point->y))
    {
        return (SCL_INVALID_INPUT);
    }

    /* Check curve length, to avoid overflow on stack allocation */
    if ((ECDSA_MAX_32B_WORDSIZE < curve_params->curve_wsize) ||
        (ECDSA_MIN_32B_WORDSIZE > curve_params->curve_wsize))
    {
        return (SCL_INVALID_LENGTH);
    }

    {
        uint32_t point_x[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t point_y[curve_params->curve_wsize] __attribute__((aligned(8)));

        memset(point_x, 0, sizeof(point_x));
        memset(point_y, 0, sizeof(point_x));

        ecc_bignum_affine_point_t point_bn = {.x = (uint64_t *)point_x,
                                              .y = (uint64_t *)point_y};

        copy_swap_array((uint8_t *)point_x, point->x,
                        curve_params->curve_bsize);
        copy_swap_array((uint8_t *)point_y, point->y,
                        curve_params->curve_bsize);

        result = soft_ecc_point_on_curve_internal(
            scl, curve_params, (ecc_bignum_affine_const_point_t *)&point_bn);
    }

    return (result);
}

static int32_t soft_ecc_pubkey_generation_internal(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const uint64_t *const priv_key, ecc_bignum_affine_point_t *const pub_key)
{
    int32_t result;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == pub_key) ||
        (NULL == priv_key))
    {
        return (SCL_INVALID_INPUT);
    }

    result = soft_ecc_mult_coz(scl, curve_params, curve_params->g, priv_key,
                               curve_params->curve_wsize, pub_key);
    if (SCL_OK != result)
    {
        return (result);
    }

    result = soft_ecc_point_on_curve_internal(
        scl, curve_params, (ecc_bignum_affine_const_point_t *)pub_key);
    if (SCL_OK != result)
    {
        return (result);
    }

    return (SCL_OK);
}

int32_t soft_ecc_pubkey_generation(const metal_scl_t *const scl,
                                   const ecc_curve_t *const curve_params,
                                   const uint8_t *const priv_key,
                                   ecc_affine_point_t *const pub_key)
{
    int32_t result;

    ecc_bignum_affine_point_t pub_key_bn;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == pub_key) ||
        (NULL == priv_key))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == pub_key->x) || (NULL == pub_key->y))
    {
        return (SCL_INVALID_INPUT);
    }

    /* Check curve length, to avoid overflow on stack allocation */
    if ((ECDSA_MAX_32B_WORDSIZE < curve_params->curve_wsize) ||
        (ECDSA_MIN_32B_WORDSIZE > curve_params->curve_wsize))
    {
        return (SCL_INVALID_LENGTH);
    }

    {
        uint32_t pubkey_bn_x[curve_params->curve_wsize]
            __attribute__((aligned(8)));
        uint32_t pubkey_bn_y[curve_params->curve_wsize]
            __attribute__((aligned(8)));
        uint32_t privkey_bn[curve_params->curve_wsize]
            __attribute__((aligned(8)));

        memset(privkey_bn, 0, sizeof(privkey_bn));

        copy_swap_array((uint8_t *)privkey_bn, priv_key,
                        curve_params->curve_bsize);

        pub_key_bn.x = (uint64_t *)pubkey_bn_x;
        pub_key_bn.y = (uint64_t *)pubkey_bn_y;

        result = soft_ecc_pubkey_generation_internal(
            scl, curve_params, (uint64_t *)privkey_bn, &pub_key_bn);
        if (SCL_OK != result)
        {
            return (result);
        }

        copy_swap_array(pub_key->x, (uint8_t *)pubkey_bn_x,
                        curve_params->curve_bsize);
        copy_swap_array(pub_key->y, (uint8_t *)pubkey_bn_y,
                        curve_params->curve_bsize);
    }

    return (result);
}

int32_t soft_ecc_keypair_generation(const metal_scl_t *const scl,
                                    const ecc_curve_t *const curve_params,
                                    uint8_t *const priv_key,
                                    ecc_affine_point_t *const pub_key)
{
    int32_t result;
    int32_t result_2;
    size_t i;
    ecc_bignum_affine_point_t pub_key_bn;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == pub_key))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == pub_key->x) || (NULL == pub_key->y))
    {
        return (SCL_INVALID_INPUT);
    }

    /* Check curve length, to avoid overflow on stack allocation */
    if ((ECDSA_MAX_32B_WORDSIZE < curve_params->curve_wsize) ||
        (ECDSA_MIN_32B_WORDSIZE > curve_params->curve_wsize))
    {
        return (SCL_INVALID_LENGTH);
    }

    if ((NULL == scl->trng_func.get_data) ||
        (NULL == scl->bignum_func.is_null) ||
        (NULL == scl->bignum_func.compare))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    {
        uint32_t pubkey_bn_x[curve_params->curve_wsize]
            __attribute__((aligned(8)));
        uint32_t pubkey_bn_y[curve_params->curve_wsize]
            __attribute__((aligned(8)));
        uint32_t privkey_bn[curve_params->curve_wsize]
            __attribute__((aligned(8)));

        memset(privkey_bn, 0, sizeof(privkey_bn));

        /* 3. randomly generate priv_key [1,n-1] */
        do
        {
            for (i = 0; i < curve_params->curve_wsize; i++)
            {
                result = scl->trng_func.get_data(scl, &privkey_bn[i]);
                if (SCL_OK != result)
                {
                    return (result);
                }
            }

            truncate_array((uint8_t *)privkey_bn,
                           curve_params->curve_wsize * sizeof(uint32_t),
                           curve_params->curve_bitsize);

            result = scl->bignum_func.compare(scl, (uint64_t *)privkey_bn,
                                              curve_params->n,
                                              curve_params->curve_wsize);

            result_2 = scl->bignum_func.is_null(scl, privkey_bn,
                                                curve_params->curve_wsize);

        } while ((result >= 0) || (false != result_2));

        pub_key_bn.x = (uint64_t *)pubkey_bn_x;
        pub_key_bn.y = (uint64_t *)pubkey_bn_y;

        result = soft_ecc_pubkey_generation_internal(
            scl, curve_params, (uint64_t *)privkey_bn, &pub_key_bn);
        if (SCL_OK != result)
        {
            return (result);
        }

        copy_swap_array(priv_key, (uint8_t *)privkey_bn,
                        curve_params->curve_bsize);
        copy_swap_array(pub_key->x, (uint8_t *)pubkey_bn_x,
                        curve_params->curve_bsize);
        copy_swap_array(pub_key->y, (uint8_t *)pubkey_bn_y,
                        curve_params->curve_bsize);
    }

    return (SCL_OK);
}
