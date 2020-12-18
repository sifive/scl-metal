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
 * @file soft_ecdh.c
 * @brief software Elliptic Curve Diffie-Hellman algorithm implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <backend/api/utils.h>

#include <scl/scl_retdefs.h>

#include <backend/api/asymmetric/ecc/ecdh.h>
#include <backend/software/asymmetric/ecc/soft_ecc.h>
#include <backend/software/asymmetric/ecc/soft_ecc_keygen.h>
#include <backend/software/asymmetric/ecc/soft_ecdh.h>

int32_t soft_ecdh(const metal_scl_t *const scl,
                  const ecc_curve_t *const curve_params,
                  const uint8_t *const priv_key,
                  const ecc_affine_const_point_t *const peer_pub_key,
                  uint8_t *const shared_secret, size_t *const shared_secret_len)
{
    int32_t result;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == priv_key) ||
        (NULL == peer_pub_key) || (NULL == shared_secret) ||
        (NULL == shared_secret_len))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == peer_pub_key->x) || (NULL == peer_pub_key->y))
    {
        return (SCL_INVALID_INPUT);
    }

    /* Check curve length */
    if ((ECDSA_MAX_32B_WORDSIZE < curve_params->curve_wsize) ||
        (ECDSA_MIN_32B_WORDSIZE > curve_params->curve_wsize))
    {
        return (SCL_INVALID_LENGTH);
    }

    if (curve_params->curve_bsize > *shared_secret_len)
    {
        return (SCL_INVALID_LENGTH);
    }

    {
        /* input big integer */
        uint32_t priv_key_bn[curve_params->curve_wsize]
            __attribute__((aligned(8)));
        uint32_t pub_key_x_bn[curve_params->curve_wsize]
            __attribute__((aligned(8)));
        uint32_t pub_key_y_bn[curve_params->curve_wsize]
            __attribute__((aligned(8)));

        ecc_bignum_affine_point_t pub_key_bn = {.x = (uint64_t *)pub_key_x_bn,
                                                .y = (uint64_t *)pub_key_y_bn};

        /* output big integer */
        uint32_t shared_x_bn[curve_params->curve_wsize]
            __attribute__((aligned(8)));
        uint32_t shared_y_bn[curve_params->curve_wsize]
            __attribute__((aligned(8)));

        ecc_bignum_affine_point_t shared_bn = {.x = (uint64_t *)shared_x_bn,
                                               .y = (uint64_t *)shared_y_bn};

        memset(priv_key_bn, 0, sizeof(priv_key_bn));
        memset(pub_key_x_bn, 0, sizeof(pub_key_x_bn));
        memset(pub_key_y_bn, 0, sizeof(pub_key_y_bn));

        memset(shared_x_bn, 0, sizeof(shared_x_bn));
        memset(shared_y_bn, 0, sizeof(shared_y_bn));

        copy_swap_array((uint8_t *)priv_key_bn, priv_key,
                        curve_params->curve_bsize);
        copy_swap_array((uint8_t *)pub_key_x_bn, peer_pub_key->x,
                        curve_params->curve_bsize);
        copy_swap_array((uint8_t *)pub_key_y_bn, peer_pub_key->y,
                        curve_params->curve_bsize);

        result = soft_ecc_point_on_curve_internal(
            scl, curve_params, (ecc_bignum_affine_const_point_t *)&pub_key_bn);
        if (SCL_OK != result)
        {
            return (result);
        }

        result = soft_ecc_mult_coz(
            scl, curve_params, (ecc_bignum_affine_const_point_t *)&pub_key_bn,
            (uint64_t *)priv_key_bn, curve_params->curve_wsize, &shared_bn);
        if (SCL_OK != result)
        {
            return (result);
        }

        copy_swap_array(shared_secret, (uint8_t *)shared_bn.x,
                        curve_params->curve_bsize);

        *shared_secret_len = curve_params->curve_bsize;
    }

    return (SCL_OK);
}
