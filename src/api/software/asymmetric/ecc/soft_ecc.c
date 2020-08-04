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
 * @file soft_ecc.c
 * @brief software elliptic curve cryptography implementation (mostly operation
 * on elliptic curves)
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <string.h>

#include <api/macro.h>
#include <api/utils.h>

#include <scl/scl_retdefs.h>

#include <api/asymmetric/ecc/ecc.h>
#include <api/software/asymmetric/ecc/soft_ecc.h>

/* SECP256R1 */
static const uint32_t ecc_xg_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0xd898c296, 0xf4a13945, 0x2deb33a0,
                                   0x77037d81, 0x63a440f2, 0xf8bce6e5,
                                   0xe12c4247, 0x6b17d1f2};
static const uint32_t ecc_yg_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0x37bf51f5, 0xcbb64068, 0x6b315ece,
                                   0x2bce3357, 0x7c0f9e16, 0x8ee7eb4a,
                                   0xfe1a7f9b, 0x4fe342e2};
static const uint32_t ecc_a_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0xfffffffc, 0xffffffff, 0xffffffff,
                                   0x00000000, 0x00000000, 0x00000000,
                                   0x00000001, 0xffffffff};
static const uint32_t ecc_b_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0x27d2604b, 0x3bce3c3e, 0xcc53b0f6,
                                   0x651d06b0, 0x769886bc, 0xb3ebbd55,
                                   0xaa3a93e7, 0x5ac635d8};
static const uint32_t ecc_p_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0xffffffff, 0xffffffff, 0xffffffff,
                                   0x00000000, 0x00000000, 0x00000000,
                                   0x00000001, 0xffffffff};
static const uint32_t ecc_n_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0xfc632551, 0xf3b9cac2, 0xa7179e84,
                                   0xbce6faad, 0xffffffff, 0xffffffff,
                                   0x00000000, 0xffffffff};
static const uint32_t ecc_precomputed_1_x_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0xc420924a, 0x39912513, 0x487cab57,
                                   0x00b60867, 0x48adde64, 0x5afb62de,
                                   0x1e67a44b, 0x0b197a2e};
static const uint32_t ecc_precomputed_1_y_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0x2efba5a0, 0x461ac4c7, 0x47404cbf,
                                   0xf0a0ab11, 0x9839be03, 0xa990c7a2,
                                   0x0c6bac1e, 0x5b5fc4ce};
static const uint32_t ecc_inverse_2_p256r1[ECC_SECP256R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {0x00000000, 0x00000000, 0x80000000,
                                   0x00000000, 0x00000000, 0x80000000,
                                   0x80000000, 0x7fffffff};

static const uint32_t ecc_square_p_p256r1[ECC_SECP256R1_32B_WORDS_SIZE * 2]
    __attribute__((aligned(8))) = {
        0x00000001, 0x00000000, 0x00000000, 0xfffffffe, 0xffffffff, 0xffffffff,
        0xfffffffe, 0x00000001, 0xfffffffe, 0x00000001, 0xfffffffe, 0x00000001,
        0x00000001, 0xfffffffe, 0x00000002, 0xfffffffe};

const ecc_curve_t ecc_secp256r1 = {ecc_a_p256r1,
                                   ecc_b_p256r1,
                                   ecc_p_p256r1,
                                   ecc_n_p256r1,
                                   ecc_xg_p256r1,
                                   ecc_yg_p256r1,
                                   ecc_inverse_2_p256r1,
                                   ecc_square_p_p256r1,
                                   ecc_precomputed_1_x_p256r1,
                                   ecc_precomputed_1_y_p256r1,
                                   ECC_SECP256R1_32B_WORDS_SIZE,
                                   ECC_SECP256R1_BYTESIZE,
                                   ECC_SECP256R1};

/* SECP384R1 */
static const uint32_t ecc_xg_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x72760ab7, 0x3a545e38, 0xbf55296c, 0x5502f25d, 0x82542a38, 0x59f741e0,
        0x8ba79b98, 0x6e1d3b62, 0xf320ad74, 0x8eb1c71e, 0xbe8b0537, 0xaa87ca22};
static const uint32_t ecc_yg_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x90ea0e5f, 0x7a431d7c, 0x1d7e819d, 0x0a60b1ce, 0xb5f0b8c0, 0xe9da3113,
        0x289a147c, 0xf8f41dbd, 0x9292dc29, 0x5d9e98bf, 0x96262c6f, 0x3617de4a};
static const uint32_t ecc_a_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xfffffffc, 0x00000000, 0x00000000, 0xffffffff, 0xfffffffe, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
static const uint32_t ecc_b_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xd3ec2aef, 0x2a85c8ed, 0x8a2ed19d, 0xc656398d, 0x5013875a, 0x0314088f,
        0xfe814112, 0x181d9c6e, 0xe3f82d19, 0x988e056b, 0xe23ee7e4, 0xb3312fa7};
static const uint32_t ecc_p_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xfffffffe, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
static const uint32_t ecc_n_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xccc52973, 0xecec196a, 0x48b0a77a, 0x581a0db2, 0xf4372ddf, 0xc7634d81,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
static const uint32_t ecc_precomputed_1_x_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xa7dc885c, 0xd8ed2ff2, 0x12f8e1fa, 0xb499e34b, 0x37d205ce, 0x7eb2ff39,
        0xa5127bf6, 0x9f1383e8, 0xd6c96f1b, 0x09e7ad61, 0xf514dae5, 0x7fbbe67c};
static const uint32_t ecc_precomputed_1_y_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xb0437ac0, 0x840182e0, 0xde9d6cba, 0xdf52f874, 0x6fee5e30, 0xc8efc7be,
        0xd33df9bd, 0xd59af65a, 0x87f4a1b5, 0xd5141a5d, 0xf5ca9b9d, 0xf38aabe5};
static const uint32_t ecc_inverse_2_p384r1[ECC_SECP384R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x80000000, 0x00000000, 0x80000000, 0x7fffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff};

const ecc_curve_t ecc_secp384r1 = {ecc_a_p384r1,
                                   ecc_b_p384r1,
                                   ecc_p_p384r1,
                                   ecc_n_p384r1,
                                   ecc_xg_p384r1,
                                   ecc_yg_p384r1,
                                   ecc_inverse_2_p384r1,
                                   NULL,
                                   ecc_precomputed_1_x_p384r1,
                                   ecc_precomputed_1_y_p384r1,
                                   ECC_SECP384R1_32B_WORDS_SIZE,
                                   ECC_SECP384R1_BYTESIZE,
                                   ECC_SECP384R1};

/* SECP521R1 */
static const uint32_t ecc_xg_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xc2e5bd66, 0xf97e7e31, 0x856a429b, 0x3348b3c1, 0xa2ffa8de, 0xfe1dc127,
        0xefe75928, 0xa14b5e77, 0x6b4d3dba, 0xf828af60, 0x053fb521, 0x9c648139,
        0x2395b442, 0x9e3ecb66, 0x0404e9cd, 0x858e06b7, 0x000000c6};
static const uint32_t ecc_yg_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x9fd16650, 0x88be9476, 0xa272c240, 0x353c7086, 0x3fad0761, 0xc550b901,
        0x5ef42640, 0x97ee7299, 0x273e662c, 0x17afbd17, 0x579b4468, 0x98f54449,
        0x2c7d1bd9, 0x5c8a5fb4, 0x9a3bc004, 0x39296a78, 0x00000118};
static const uint32_t ecc_a_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xfffffffc, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff};
static const uint32_t ecc_b_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x6b503f00, 0xef451fd4, 0x3d2c34f1, 0x3573df88, 0x3bb1bf07, 0x1652c0bd,
        0xec7e937b, 0x56193951, 0x8ef109e1, 0xb8b48991, 0x99b315f3, 0xa2da725b,
        0xb68540ee, 0x929a21a0, 0x8e1c9a1f, 0x953eb961, 0x00000051};
static const uint32_t ecc_p_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff};
static const uint32_t ecc_n_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x91386409, 0xbb6fb71e, 0x899c47ae, 0x3bb5c9b8, 0xf709a5d0, 0x7fcc0148,
        0xbf2f966b, 0x51868783, 0xfffffffa, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff};
static const uint32_t ecc_precomputed_1_x_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x6b4c3f67, 0x82e05142, 0x3fc34315, 0x83049259, 0x972d1c60, 0x2b17027d,
        0x06941699, 0x650bd0df, 0xbf06dea4, 0xc960bca9, 0xf6bf6453, 0xc9b131ee,
        0x6e2a0bd0, 0xc7865c90, 0x5d5f6799, 0xffb964e0, 0x00000033};
static const uint32_t ecc_precomputed_1_y_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x16056e76, 0xcd247a09, 0x4aabbfce, 0xc0f214f1, 0x8fb1cf42, 0x7b7ba942,
        0x79dfcd33, 0x521e44f1, 0x030cfa52, 0x72151cc5, 0x3f763269, 0x6e731597,
        0xfa5b5eb9, 0x15eea047, 0xc9cc275d, 0x6870c5d0, 0x0000017c};
static const const uint32_t ecc_inverse_2_p521r1[ECC_SECP521R1_32B_WORDS_SIZE]
    __attribute__((aligned(8))) = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000100};

const ecc_curve_t ecc_secp521r1 = {ecc_a_p521r1,
                                   ecc_b_p521r1,
                                   ecc_p_p521r1,
                                   ecc_n_p521r1,
                                   ecc_xg_p521r1,
                                   ecc_yg_p521r1,
                                   ecc_inverse_2_p521r1,
                                   NULL,
                                   ecc_precomputed_1_x_p521r1,
                                   ecc_precomputed_1_y_p521r1,
                                   ECC_SECP521R1_32B_WORDS_SIZE,
                                   ECC_SECP521R1_BYTESIZE,
                                   ECC_SECP521R1};

void soft_ecc_affine_copy(const ecc_bignum_affine_point_t *const src,
                          ecc_bignum_affine_point_t *const dst,
                          size_t curve_nb_32b_words)
{
    memcpy(dst->x, src->x, curve_nb_32b_words * sizeof(uint32_t));
    memcpy(dst->y, src->y, curve_nb_32b_words * sizeof(uint32_t));
}

void soft_ecc_affine_zeroize(ecc_bignum_affine_point_t *const point,
                             size_t curve_nb_32b_words)
{
    memset((volatile uint32_t *)point->x, 0,
           curve_nb_32b_words * sizeof(uint32_t));
    memset((volatile uint32_t *)point->y, 0,
           curve_nb_32b_words * sizeof(uint32_t));
}

void soft_ecc_jacobian_copy(const ecc_bignum_jacobian_point_t *const src,
                            ecc_bignum_jacobian_point_t *const dst,
                            size_t curve_nb_32b_words)
{
    memcpy(dst->x, src->x, curve_nb_32b_words * sizeof(uint32_t));
    memcpy(dst->y, src->y, curve_nb_32b_words * sizeof(uint32_t));
    memcpy(dst->z, src->z, curve_nb_32b_words * sizeof(uint32_t));
}

void soft_ecc_affine_zeroize(ecc_bignum_jacobian_point_t *const point,
                             size_t curve_nb_32b_words)
{
    memset((volatile uint32_t *)point->x, 0,
           curve_nb_32b_words * sizeof(uint32_t));
    memset((volatile uint32_t *)point->y, 0,
           curve_nb_32b_words * sizeof(uint32_t));
    memset((volatile uint32_t *)point->z, 0,
           curve_nb_32b_words * sizeof(uint32_t));
}

int32_t soft_ecc_convert_affine_to_jacobian(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_point_t *const in,
    ecc_bignum_jacobian_point_t *const out, size_t nb_32b_words, )
{
    if ((NULL == scl) || (NULL == in) || (NULL == out) ||
        (NULL == curve_params))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == in->x) || (NULL == in->y) || (NULL == out->x) ||
        (NULL == out->y) || (NULL == out->z))
    {
        return (SCL_INVALID_INPUT);
    }

    /* check length consistency */
    if (nb_32b_words != curve_params->curve_wsize)
    {
        return (SCL_INVALID_LENGTH);
    }

    /* conversion from x:y to x*z^2:y*z^3:z, with z=1, so x,y,1 */
    memcpy(out->x, in->x, nb_32b_words * sizeof(uint32_t));
    memcpy(out->y, in->y, nb_32b_words * sizeof(uint32_t));
    memset(out->z, 0, nb_32b_words * sizeof(uint32_t));
    out->z[0] = 1;
    *((uint32_t *)&out->z[0]) = 1;

    return (SCL_OK);
}

int32_t soft_ecc_convert_jacobian_to_affine(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_jacobian_point_t *const in,
    ecc_bignum_affine_point_t *const out, size_t nb_32b_words)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == in) || (NULL == out) ||
        (NULL == curve_params))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == in->x) || (NULL == in->y) || (NULL == in->z) ||
        (NULL == out->x) || (NULL == out->y))
    {
        return (SCL_INVALID_INPUT);
    }

    /* check length consistency */
    if (nb_32b_words != curve_params->curve_wsize)
    {
        return (SCL_INVALID_LENGTH);
    }

    if ((NULL == scl->bignum_func.set_modulus) ||
        (NULL == scl->bignum_func.mod_square) ||
        (NULL == scl->bignum_func.mod_inv) ||
        (NULL == scl->bignum_func.mod_mult))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    {
        uint32_t tmp[nb_32b_words] __attribute__((aligned(8)));
        uint32_t tmp1[nb_32b_words] __attribute__((aligned(8)));

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /**
         * x:y:z corresponds to x/z^2:y/z^3
         * z^2
         */
        result = scl->bignum_func.mod_square(scl, &bignum_ctx, in->z, tmp,
                                             nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* z^-2 (modular inversion) */
        result =
            scl->bignum_func.mod_inv(scl, &bignum_ctx, tmp, tmp1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, in->x, tmp1,
                                           out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* z^3 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, in->z, tmp, tmp,
                                           nb_32b_words);

        // z^-3 (modular inversion)
        result =
            scl->bignum_func.mod_inv(scl, &bignum_ctx, tmp, tmp1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, in->y, tmp1,
                                           out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }
    }
    return (SCL_OK);
}
