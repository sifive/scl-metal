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
 * @file soft_ecdsa.c
 * @brief software elliptic curve digital signature algorithm implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <string.h>

#include <api/macro.h>
#include <api/utils.h>

#include <scl/scl_retdefs.h>

#include <api/asymmetric/ecc/ecdsa.h>
#include <api/software/asymmetric/ecc/soft_ecc.h>
#include <api/software/asymmetric/ecc/soft_ecdsa.h>

int32_t soft_ecdsa_verification(const metal_scl_t *const scl,
                                const ecc_affine_point_t *const pub_key,
                                const ecc_affine_point_t *const signature,
                                const uint8_t *const hash, size_t hash_len,
                                const ecc_curve_t *const curve_params)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;
    size_t i, j, ki_li;
    size_t nb_64_bits_words_curve;
    size_t n;

    if ((NULL == scl) || (NULL == pub_key) || (NULL == signature) ||
        (NULL == hash) || (NULL == curve_params))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == pub_key->x) || (NULL == pub_key->y) ||
        (NULL == signature->x) || (NULL == signature->y) ||
        (NULL == curve_params->n))

    {
        return (SCL_INVALID_INPUT);
    }

    /* Check curve length */
    if ((ECDSA_MAX_32B_WORDSIZE < curve_params->curve_wsize) ||
        (ECDSA_MIN_32B_WORDSIZE > curve_params->curve_wsize))
    {
        return (SCL_INVALID_LENGTH);
    }

    nb_64_bits_words_curve =
        curve_params->curve_wsize / 2 + curve_params->curve_wsize % 2;

    {
        /* signature intermediate buffer to swap  */
        uint32_t r[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t s[curve_params->curve_wsize] __attribute__((aligned(8)));

        /**
         * The notation used here follow the ones in Wikipedia
         */
        uint32_t e[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t z[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t u1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t u2[curve_params->curve_wsize] __attribute__((aligned(8)));

        uint32_t x1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t y1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t z1[curve_params->curve_wsize] __attribute__((aligned(8)));

        /* Public key components */
        uint32_t xq[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t yq[curve_params->curve_wsize] __attribute__((aligned(8)));

        ecc_bignum_affine_point_t point_aff;
        ecc_bignum_jacobian_point_t point_jac;

        /** algo 3.48 in GtECC (Guide to Elliptic Curve Cryptography) with w=2,
         * so 2^w=4, so i=0..3, j=0..3 the array for storing the precomputed
         * values is 16-point large */
#define SCL_ECDSA_WINDOW_WIDTH 2
#define SCL_ECDSA_ARRAY_SIZE                                                   \
    (1 << SCL_ECDSA_WINDOW_WIDTH) * (1 << SCL_ECDSA_WINDOW_WIDTH)

        /**
         * variables that contain the precomputed values
         * xP + jQ window method matrix
         */
        ecc_bignum_jacobian_point_t ip_jq[SCL_ECDSA_ARRAY_SIZE];

        uint64_t ip_jq_x[SCL_ECDSA_ARRAY_SIZE][nb_64_bits_words_curve];
        uint64_t ip_jq_y[SCL_ECDSA_ARRAY_SIZE][nb_64_bits_words_curve];
        uint64_t ip_jq_z[SCL_ECDSA_ARRAY_SIZE][nb_64_bits_words_curve];

        /* Copy-swap signature */
        memset(r, 0, curve_params->curve_wsize * sizeof(uint32_t));
        memset(s, 0, curve_params->curve_wsize * sizeof(uint32_t));
        copy_swap_array((uint8_t *)r, signature->x, curve_params->curve_bsize);
        copy_swap_array((uint8_t *)s, signature->y, curve_params->curve_bsize);

        /* Check that r and s are in the interval [1, n-1] */
        result = scl->bignum_func.compare(scl, (uint64_t *)r, curve_params->n,
                                          curve_params->curve_wsize);
        if (result >= 0)
        {
            result = SCL_ERROR;
            goto cleanup;
        }

        result = scl->bignum_func.compare(scl, (uint64_t *)s, curve_params->n,
                                          curve_params->curve_wsize);
        if (result >= 0)
        {
            result = SCL_ERROR;
            goto cleanup;
        }

        result = scl->bignum_func.is_null(scl, r, curve_params->curve_wsize);
        if (false != result)
        {
            result = SCL_ERROR;
            goto cleanup;
        }

        result = scl->bignum_func.is_null(scl, s, curve_params->curve_wsize);
        if (false != result)
        {
            result = SCL_ERROR;
            goto cleanup;
        }

        /* Copy hash into e */
        memset(e, 0, curve_params->curve_wsize * sizeof(uint32_t));
        copy_swap_array(
            (uint8_t *)e, hash,
            MIN(hash_len, curve_params->curve_wsize * sizeof(uint32_t)));

        /* set modulus context */
        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->n,
                                              curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Compute z = s^(-1) mod n */
        result =
            scl->bignum_func.mod_inv(scl, &bignum_ctx, (uint64_t *)s,
                                     (uint64_t *)z, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Compute u1 = e.z mod n */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)e,
                                           (uint64_t *)z, (uint64_t *)u1,
                                           curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Compute u2 = r.z mod n */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)r,
                                           (uint64_t *)z, (uint64_t *)u2,
                                           curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Public key */
        memset(xq, 0, curve_params->curve_wsize * sizeof(uint32_t));
        copy_swap_array((uint8_t *)xq, pub_key->x, curve_params->curve_bsize);
        memset(yq, 0, curve_params->curve_wsize * sizeof(uint32_t));
        copy_swap_array((uint8_t *)yq, pub_key->y, curve_params->curve_bsize);

        /* ip_jq structure adapted to the functions APIs */
        for (i = 0; i < SCL_ECDSA_ARRAY_SIZE; i++)
        {
            ip_jq[i].x = &ip_jq_x[i][0];
            ip_jq[i].y = &ip_jq_y[i][0];
            ip_jq[i].z = &ip_jq_z[i][0];
        }

        /* Compute 1.P */
        result = soft_ecc_convert_affine_to_jacobian(scl, curve_params,
                                                     curve_params->g, &ip_jq[1],
                                                     curve_params->curve_wsize);
        if (SCL_OK != result)
        {
            goto cleanup;
        }
        /* Compute 2.P */
        result = soft_ecc_double_jacobian(scl, curve_params, &ip_jq[1],
                                          &ip_jq[2], curve_params->curve_wsize);
        if (SCL_OK != result)
        {
            goto cleanup;
        }
        /* Compute 3.P */
        result = soft_ecc_add_jacobian_jacobian(scl, curve_params, &ip_jq[1],
                                                &ip_jq[2], &ip_jq[3],
                                                curve_params->curve_wsize);
        if (SCL_OK != result)
        {
            goto cleanup;
        }

        /* point contains the public key */
        point_aff.x = (uint64_t *)xq;
        point_aff.y = (uint64_t *)yq;

        /* Compute 1.Q */
        result = soft_ecc_convert_affine_to_jacobian(scl, curve_params,
                                                     &point_aff, &ip_jq[4],
                                                     curve_params->curve_wsize);
        if (SCL_OK != result)
        {
            goto cleanup;
        }
        /* Compute 2.Q */
        result = soft_ecc_double_jacobian(scl, curve_params, &ip_jq[4],
                                          &ip_jq[8], curve_params->curve_wsize);
        if (SCL_OK != result)
        {
            goto cleanup;
        }
        /* Compute 3.Q */
        result = soft_ecc_add_jacobian_jacobian(scl, curve_params, &ip_jq[4],
                                                &ip_jq[8], &ip_jq[12],
                                                curve_params->curve_wsize);
        if (SCL_OK != result)
        {
            goto cleanup;
        }

        /* computing all the combinations of iP + jQ */
        for (j = 4; j <= 12; j += 4)
        {
            for (i = 0; i < 3; i++)
            {
                result = soft_ecc_add_jacobian_jacobian(
                    scl, curve_params, &ip_jq[j], &ip_jq[i + 1],
                    &ip_jq[j + 1 + i], curve_params->curve_wsize);
                if (SCL_OK != result)
                {
                    goto cleanup;
                }
            }
        }

        n = curve_params->curve_wsize * sizeof(uint32_t) * __CHAR_BIT__;

        /* 3. r=infinite */
        memset(x1, 0, curve_params->curve_wsize * sizeof(uint32_t));
        x1[0] = 1;
        memset(y1, 0, curve_params->curve_wsize * sizeof(uint32_t));
        y1[0] = 1;
        memset(z1, 0, curve_params->curve_wsize * sizeof(uint32_t));

        point_jac.x = (uint64_t *)x1;
        point_jac.y = (uint64_t *)y1;
        point_jac.z = (uint64_t *)z1;

        /**
         * 4.
         * Note : time is spent here
         */
        i = (n / SCL_ECDSA_WINDOW_WIDTH);

        while (i != 0)
        {
            i--;

            /** 4.1 */
            for (j = 0; j < SCL_ECDSA_WINDOW_WIDTH; j++)
            {
                result = soft_ecc_double_jacobian(scl, curve_params, &point_jac,
                                                  &point_jac,
                                                  curve_params->curve_wsize);
                if (SCL_OK != result)
                {
                    goto cleanup;
                }
            }

            /**
             * 4.2 two-bit (due to windows width : SCL_ECDSA_WINDOW_WIDTH)
             * wide at a time
             */

            ki_li = (soft_ecc_bit_extract(u1, i * 2) ^
                     (soft_ecc_bit_extract(u1, i * 2 + 1) << 1)) ^
                    ((soft_ecc_bit_extract(u2, i * 2) ^
                      (soft_ecc_bit_extract(u2, i * 2 + 1) << 1))
                     << 2);
            if (0 != ki_li)
            {
                result = soft_ecc_add_jacobian_jacobian(
                    scl, curve_params, &ip_jq[ki_li], &point_jac, &point_jac,
                    curve_params->curve_wsize);
                if (SCL_OK != result)
                {
                    goto cleanup;
                }
            }
        }

        /* 4. (x1,y1)=u1.G+u2.Q */
        point_aff.x = (uint64_t *)x1;
        point_aff.y = (uint64_t *)y1;

        result = soft_ecc_convert_jacobian_to_affine(scl, curve_params,
                                                     &point_jac, &point_aff,
                                                     curve_params->curve_wsize);
        if (SCL_OK != result)
        {
            goto cleanup;
        }

        /* v=x1 mod n (using z1 as v) */
        result = scl->bignum_func.mod(
            scl, (uint64_t *)x1, curve_params->curve_wsize, curve_params->n,
            curve_params->curve_wsize, (uint64_t *)z1);
        if (SCL_OK != result)
        {
            goto cleanup;
        }

        /* if (r==v) the signature is ok */
        if (0 != memcmp(r, z1, curve_params->curve_wsize * sizeof(uint32_t)))
        {
            result = SCL_ERROR;
            goto cleanup;
        }
    }

    result = SCL_OK;
cleanup:
    return (result);
}
