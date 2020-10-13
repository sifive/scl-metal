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
 * @file scl_ecc_keygen.c
 * @brief defines the generic ECC key generation function interface, where the
 * hash function is transmitted as a parameter.
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <scl/scl_ecc_keygen.h>
#include <scl/scl_retdefs.h>

int32_t scl_ecc_key_on_curve(const metal_scl_t *const scl,
                             const ecc_curve_t *const curve_params,
                             const ecc_affine_const_point_t *const point)
{
    if ((NULL == scl))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->ecc_func.point_on_curve))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (scl->ecc_func.point_on_curve(scl, curve_params, point));
}

int32_t scl_ecc_pubkey_generation(const metal_scl_t *const scl,
                                  const ecc_curve_t *const curve_params,
                                  const uint8_t *const priv_key,
                                  ecc_affine_point_t *const pub_key)
{
    if ((NULL == scl))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->ecc_func.pubkey_generation))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (
        scl->ecc_func.pubkey_generation(scl, curve_params, priv_key, pub_key));
}

int32_t scl_ecc_keypair_generation(const metal_scl_t *const scl,
                                   const ecc_curve_t *const curve_params,
                                   uint8_t *const priv_key,
                                   ecc_affine_point_t *const pub_key)
{
    if ((NULL == scl))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->ecc_func.keypair_generation))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    return (
        scl->ecc_func.keypair_generation(scl, curve_params, priv_key, pub_key));
}
