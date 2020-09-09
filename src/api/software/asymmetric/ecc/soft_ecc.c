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

#include <api/software/bignumbers/soft_bignumbers.h>

/* SECP256R1 */
static uint64_t ecc_xg_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] = {
    0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2,
    0x6b17d1f2e12c4247};
static uint64_t ecc_yg_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] = {
    0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16,
    0x4fe342e2fe1a7f9b};
static const uint64_t ecc_a_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] = {
    0xfffffffffffffffc, 0x00000000ffffffff, 0x0000000000000000,
    0xffffffff00000001};
static const uint64_t ecc_b_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] = {
    0x3bce3c3e27d2604b, 0x651d06b0cc53b0f6, 0xb3ebbd55769886bc,
    0x5ac635d8aa3a93e7};
static const uint64_t ecc_p_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] = {
    0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000,
    0xffffffff00000001};
static const uint64_t ecc_n_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] = {
    0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff,
    0xffffffff00000000};
static const uint64_t ecc_precomputed_1_x_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] =
    {0x39912513c420924a, 0x00b60867487cab57, 0x5afb62de48adde64,
     0x0b197a2e1e67a44b};
static const uint64_t ecc_precomputed_1_y_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] =
    {0x461ac4c72efba5a0, 0xf0a0ab1147404cbf, 0xa990c7a29839be03,
     0x5b5fc4ce0c6bac1e};
static const uint64_t ecc_inverse_2_p256r1[ECC_SECP256R1_64B_WORDS_SIZE] = {
    0x0000000000000000, 0x0000000080000000, 0x8000000000000000,
    0x7fffffff80000000};

static const uint64_t ecc_square_p_p256r1[ECC_SECP256R1_64B_WORDS_SIZE * 2] = {
    0x0000000000000001, 0xfffffffe00000000, 0xffffffffffffffff,
    0x00000001fffffffe, 0x00000001fffffffe, 0x00000001fffffffe,
    0xfffffffe00000001, 0xfffffffe00000002,
};

static const ecc_bignum_affine_point_t ecc_g_p256r1 = {ecc_xg_p256r1,
                                                       ecc_yg_p256r1};

const ecc_curve_t ecc_secp256r1 = {
    .a = ecc_a_p256r1,
    .b = ecc_b_p256r1,
    .p = ecc_p_p256r1,
    .n = ecc_n_p256r1,
    .g = &ecc_g_p256r1,
    .inverse_2 = ecc_inverse_2_p256r1,
    .square_p = ecc_square_p_p256r1,
    .precomputed_1_x = ecc_precomputed_1_x_p256r1,
    .precomputed_1_y = ecc_precomputed_1_y_p256r1,
    .curve_wsize = ECC_SECP256R1_32B_WORDS_SIZE,
    .curve_bsize = ECC_SECP256R1_BYTESIZE,
    .curve_bitsize = ECC_SECP256R1_BITSIZE,
    .curve = ECC_SECP256R1};

/* SECP384R1 */
static uint64_t ecc_xg_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] = {
    0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38,
    0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537};
static uint64_t ecc_yg_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] = {
    0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0,
    0xf8f41dbd289a147c, 0x5d9e98bf9292dc29, 0x3617de4a96262c6f};
static const uint64_t ecc_a_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] = {
    0x00000000fffffffc, 0xffffffff00000000, 0xfffffffffffffffe,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static const uint64_t ecc_b_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] = {
    0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,
    0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4};
static const uint64_t ecc_p_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] = {
    0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};

static const uint64_t ecc_n_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] = {
    0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static const uint64_t ecc_precomputed_1_x_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] =
    {0xd8ed2ff2a7dc885c, 0xb499e34b12f8e1fa, 0x7eb2ff3937d205ce,
     0x9f1383e8a5127bf6, 0x09e7ad61d6c96f1b, 0x7fbbe67cf514dae5};
static const uint64_t ecc_precomputed_1_y_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] =
    {0x840182e0b0437ac0, 0xdf52f874de9d6cba, 0xc8efc7be6fee5e30,
     0xd59af65ad33df9bd, 0xd5141a5d87f4a1b5, 0xf38aabe5f5ca9b9d};
static const uint64_t ecc_inverse_2_p384r1[ECC_SECP384R1_64B_WORDS_SIZE] = {
    0x0000000080000000, 0x7fffffff80000000, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff};

static const uint64_t ecc_square_p_p384r1[ECC_SECP384R1_64B_WORDS_SIZE * 2] = {
    0xFFFFFFFE00000001, 0x0000000200000000, 0xFFFFFFFE00000000,
    0x0000000200000000, 0x0000000000000001, 0x0000000000000000,
    0x00000001FFFFFFFE, 0xFFFFFFFE00000000, 0xFFFFFFFFFFFFFFFD,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};

static const ecc_bignum_affine_point_t ecc_g_p384r1 = {ecc_xg_p384r1,
                                                       ecc_yg_p384r1};

const ecc_curve_t ecc_secp384r1 = {
    .a = ecc_a_p384r1,
    .b = ecc_b_p384r1,
    .p = ecc_p_p384r1,
    .n = ecc_n_p384r1,
    .g = &ecc_g_p384r1,
    .inverse_2 = ecc_inverse_2_p384r1,
    .square_p = ecc_square_p_p384r1,
    .precomputed_1_x = ecc_precomputed_1_x_p384r1,
    .precomputed_1_y = ecc_precomputed_1_y_p384r1,
    .curve_wsize = ECC_SECP384R1_32B_WORDS_SIZE,
    .curve_bsize = ECC_SECP384R1_BYTESIZE,
    .curve_bitsize = ECC_SECP384R1_BITSIZE,
    .curve = ECC_SECP384R1};

/* SECP521R1 */
static uint64_t ecc_xg_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] = {
    0xf97e7e31c2e5bd66, 0x3348b3c1856a429b, 0xfe1dc127a2ffa8de,
    0xa14b5e77efe75928, 0xf828af606b4d3dba, 0x9c648139053fb521,
    0x9e3ecb662395b442, 0x858e06b70404e9cd, 0x00000000000000c6};
static uint64_t ecc_yg_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] = {
    0x88be94769fd16650, 0x353c7086a272c240, 0xc550b9013fad0761,
    0x97ee72995ef42640, 0x17afbd17273e662c, 0x98f54449579b4468,
    0x5c8a5fb42c7d1bd9, 0x39296a789a3bc004, 0x0000000000000118};
static const uint64_t ecc_a_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] = {
    0xfffffffffffffffc, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff};
static const uint64_t ecc_b_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] = {
    0xef451fd46b503f00, 0x3573df883d2c34f1, 0x1652c0bd3bb1bf07,
    0x56193951ec7e937b, 0xb8b489918ef109e1, 0xa2da725b99b315f3,
    0x929a21a0b68540ee, 0x953eb9618e1c9a1f, 0x0000000000000051};
static const uint64_t ecc_p_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] = {
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff};
static const uint64_t ecc_n_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] = {
    0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0,
    0x51868783bf2f966b, 0xfffffffffffffffa, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff};
static const uint64_t ecc_precomputed_1_x_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] =
    {0x82e051426b4c3f67, 0x830492593fc34315, 0x2b17027d972d1c60,
     0x650bd0df06941699, 0xc960bca9bf06dea4, 0xc9b131eef6bf6453,
     0xc7865c906e2a0bd0, 0xffb964e05d5f6799, 0x0000000000000033};
static const uint64_t ecc_precomputed_1_y_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] =
    {0xcd247a0916056e76, 0xc0f214f14aabbfce, 0x7b7ba9428fb1cf42,
     0x521e44f179dfcd33, 0x72151cc5030cfa52, 0x6e7315973f763269,
     0x15eea047fa5b5eb9, 0x6870c5d0c9cc275d, 0x000000000000017c};

static const uint64_t ecc_inverse_2_p521r1[ECC_SECP521R1_64B_WORDS_SIZE] = {
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000100};

static const uint64_t ecc_square_p_p521r1[ECC_SECP521R1_64B_WORDS_SIZE * 2] = {
    0x0000000000000001, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0xFFFFFFFFFFFFFC00,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x000000000003FFFF, 0x0000000000000000};

static const ecc_bignum_affine_point_t ecc_g_p521r1 = {ecc_xg_p521r1,
                                                       ecc_yg_p521r1};

const ecc_curve_t ecc_secp521r1 = {
    .a = ecc_a_p521r1,
    .b = ecc_b_p521r1,
    .p = ecc_p_p521r1,
    .n = ecc_n_p521r1,
    .g = &ecc_g_p521r1,
    .inverse_2 = ecc_inverse_2_p521r1,
    .square_p = ecc_square_p_p521r1,
    .precomputed_1_x = ecc_precomputed_1_x_p521r1,
    .precomputed_1_y = ecc_precomputed_1_y_p521r1,
    .curve_wsize = ECC_SECP521R1_32B_WORDS_SIZE,
    .curve_bsize = ECC_SECP521R1_BYTESIZE,
    .curve_bitsize = ECC_SECP521R1_BITSIZE,
    .curve = ECC_SECP521R1};

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
    memset(point->x, 0, curve_nb_32b_words * sizeof(uint32_t));
    memset(point->y, 0, curve_nb_32b_words * sizeof(uint32_t));
}

void soft_ecc_jacobian_copy(const ecc_bignum_jacobian_point_t *const src,
                            ecc_bignum_jacobian_point_t *const dst,
                            size_t curve_nb_32b_words)
{
    memcpy(dst->x, src->x, curve_nb_32b_words * sizeof(uint32_t));
    memcpy(dst->y, src->y, curve_nb_32b_words * sizeof(uint32_t));
    memcpy(dst->z, src->z, curve_nb_32b_words * sizeof(uint32_t));
}

void soft_ecc_jacobian_zeroize(ecc_bignum_jacobian_point_t *const point,
                               size_t curve_nb_32b_words)
{
    memset(point->x, 0, curve_nb_32b_words * sizeof(uint32_t));
    memset(point->y, 0, curve_nb_32b_words * sizeof(uint32_t));
    memset(point->z, 0, curve_nb_32b_words * sizeof(uint32_t));
}

int32_t soft_ecc_convert_affine_to_jacobian(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_affine_point_t *const in,
    ecc_bignum_jacobian_point_t *const out, size_t nb_32b_words)
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
        result = scl->bignum_func.mod_square(scl, &bignum_ctx, in->z,
                                             (uint64_t *)tmp, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* z^-2 (modular inversion) */
        result = scl->bignum_func.mod_inv(scl, &bignum_ctx, (uint64_t *)tmp,
                                          (uint64_t *)tmp1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, in->x, (uint64_t *)tmp1, out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* z^3 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, in->z, (uint64_t *)tmp,
                                      (uint64_t *)tmp, nb_32b_words);

        // z^-3 (modular inversion)
        result = scl->bignum_func.mod_inv(scl, &bignum_ctx, (uint64_t *)tmp,
                                          (uint64_t *)tmp1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, in->y, (uint64_t *)tmp1, out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }
    }
    return (SCL_OK);
}

int32_t
soft_ecc_infinite_jacobian(const metal_scl_t *const scl,
                           const ecc_bignum_jacobian_point_t *const point,
                           size_t nb_32b_words)
{
    int32_t result;
    size_t i;

    if ((NULL == scl) || (NULL == point))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == point->x) || (NULL == point->y) || (NULL == point->z))
    {
        return (SCL_INVALID_INPUT);
    }

    if (((uint32_t)point->x[0] != 1) || ((uint32_t)point->y[0] != 1))
    {
        result = (int32_t) false;
        goto cleanup;
    }

    result = scl->bignum_func.is_null(scl, (uint32_t *)point->z, nb_32b_words);
    if (SCL_OK > result)
    {
        goto cleanup;
    }
    else if ((int32_t) false == result)
    {
        goto cleanup;
    }

    for (i = 1; i < nb_32b_words; i++)
    {
        if ((((uint32_t *)point->y)[i] != 0) ||
            (((uint32_t *)point->y)[i] != 0))
        {
            result = false;
            goto cleanup;
        }
    }
    result = true;
cleanup:
    return (result);
}

int32_t soft_ecc_add_affine_affine(const metal_scl_t *const scl,
                                   const ecc_curve_t *const curve_params,
                                   const ecc_bignum_affine_point_t *const in1,
                                   const ecc_bignum_affine_point_t *const in2,
                                   ecc_bignum_affine_point_t *const out,
                                   size_t nb_32b_words)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == in1) ||
        (NULL == in2) || (NULL == out))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->bignum_func.set_modulus) ||
        (NULL == scl->bignum_func.mod_square) ||
        (NULL == scl->bignum_func.mod_add) ||
        (NULL == scl->bignum_func.mod_sub) ||
        (NULL == scl->bignum_func.mod_mult))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    /* check length consistency */
    if (nb_32b_words != curve_params->curve_wsize)
    {
        return (SCL_INVALID_LENGTH);
    }

    {
        uint32_t lambda[nb_32b_words] __attribute__((aligned(8)));
        uint32_t tmp1[nb_32b_words] __attribute__((aligned(8)));
        uint32_t tmp2[nb_32b_words] __attribute__((aligned(8)));

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, in2->x, in1->x,
                                          (uint64_t *)tmp1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_inv(scl, &bignum_ctx, (uint64_t *)tmp1,
                                          (uint64_t *)tmp2, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, in2->y, in1->y,
                                          (uint64_t *)tmp1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)tmp1,
                                           (uint64_t *)tmp2, (uint64_t *)lambda,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        // x3=lambda^2-x1-x2
        result =
            scl->bignum_func.mod_square(scl, &bignum_ctx, (uint64_t *)lambda,
                                        (uint64_t *)tmp1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result =
            scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)tmp1, in1->x,
                                     (uint64_t *)tmp2, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        // x3  =lambda^2 mod p-x1-x2
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)tmp2,
                                          in2->x, out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        // y3=lambda*(x1-x3)-y1
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, in1->x, out->x,
                                          (uint64_t *)tmp2, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda,
                                           (uint64_t *)tmp2, (uint64_t *)tmp1,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        // y3=lambda * (x1-x3)-y1
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)tmp1,
                                           in1->y, out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }
    }

    return (SCL_OK);
}

int32_t soft_ecc_add_jacobian_jacobian(
    const metal_scl_t *const scl, const ecc_curve_t *const curve_params,
    const ecc_bignum_jacobian_point_t *const in_a,
    const ecc_bignum_jacobian_point_t *const in_b,
    ecc_bignum_jacobian_point_t *const out, size_t nb_32b_words)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == in_a) ||
        (NULL == in_b) || (NULL == out))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == in_a->x) || (NULL == in_a->y) || (NULL == in_a->z) ||
        (NULL == in_b->x) || (NULL == in_b->y) || (NULL == in_b->z) ||
        (NULL == out->x) || (NULL == out->y) || (NULL == out->z))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->bignum_func.set_modulus) ||
        (NULL == scl->bignum_func.mod_square) ||
        (NULL == scl->bignum_func.mod_add) ||
        (NULL == scl->bignum_func.mod_sub) ||
        (NULL == scl->bignum_func.mod_mult))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    /* check length consistency */
    if (nb_32b_words != curve_params->curve_wsize)
    {
        return (SCL_INVALID_LENGTH);
    }

    result = soft_ecc_infinite_jacobian(scl, in_a, nb_32b_words);
    if (SCL_OK > result)
    {
        return (result);
    }
    else if (false != result)
    {
        soft_ecc_jacobian_copy(in_b, out, nb_32b_words);
        return (SCL_OK);
    }

    result = soft_ecc_infinite_jacobian(scl, in_b, nb_32b_words);
    if (SCL_OK > result)
    {
        return (result);
    }
    else if (false != result)
    {
        soft_ecc_jacobian_copy(in_a, out, nb_32b_words);
        return (SCL_OK);
    }

    {
        uint32_t a[nb_32b_words] __attribute__((aligned(8)));
        uint32_t b[nb_32b_words] __attribute__((aligned(8)));
        uint32_t c[nb_32b_words] __attribute__((aligned(8)));
        uint32_t d[nb_32b_words] __attribute__((aligned(8)));
        uint32_t t1[nb_32b_words] __attribute__((aligned(8)));
        uint32_t t2[nb_32b_words] __attribute__((aligned(8)));
        uint32_t t3[nb_32b_words] __attribute__((aligned(8)));

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = Z2^2 */
        result = scl->bignum_func.mod_square(scl, &bignum_ctx, in_b->z,
                                             (uint64_t *)t1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* a = X1 * t1 = X1 * Z2^2 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, in_a->x, (uint64_t *)t1,
                                      (uint64_t *)a, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = Z2 * t1 = Z2^3 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t1, in_b->z,
                                      (uint64_t *)t1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* b = Y1 * t1 = Y1 * Z2^3 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t1, in_a->y,
                                      (uint64_t *)b, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = Z1^2 */
        result = scl->bignum_func.mod_square(scl, &bignum_ctx, in_a->z,
                                             (uint64_t *)t1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* c = X2 * t1 = X2 * Z1^2 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, in_b->x, (uint64_t *)t1,
                                      (uint64_t *)c, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* c = c - a = X2 * Z1^2 - a */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)c,
                                          (uint64_t *)a, (uint64_t *)c,
                                          nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = Z1 * t1 = Z1^3 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t1, in_a->z,
                                      (uint64_t *)t1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* d = Y2 * t1 = Y2 * Z1^3 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t1, in_b->y,
                                      (uint64_t *)d, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* d = d - b = Y2 * Z1^3 - b */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)d,
                                          (uint64_t *)b, (uint64_t *)d,
                                          nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = c^2 */
        result = scl->bignum_func.mod_square(scl, &bignum_ctx, (uint64_t *)c,
                                             (uint64_t *)t1, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t2 = a * t1 = a * c^2 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)a,
                                           (uint64_t *)t1, (uint64_t *)t2,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = c * t1 = c^3 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)c,
                                           (uint64_t *)t1, (uint64_t *)t1,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Z3 = Z1 * Z2 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, in_a->z, in_b->z,
                                           out->z, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Z3 = Z3 * c = Z1 * Z2 * c */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, out->z,
                                           (uint64_t *)c, out->z, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* X3 = D^2 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)d,
                                           (uint64_t *)d, out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* X3 = X3 - t1 = D^2 - C^3 */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, out->x,
                                          (uint64_t *)t1, out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t3 = 2 * t2 = 2 * AC^2 */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)t2,
                                          (uint64_t *)t2, (uint64_t *)t3,
                                          nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* X3 = X3 - t3 = D^2 -C^3 - 2*AC^2 */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, out->x,
                                          (uint64_t *)t3, out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t3 = t2 - X3 = AC^2 - X3 */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)t2,
                                          out->x, (uint64_t *)t3, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t3 = D * t3 = D(AC^2 - X3)*/
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)d,
                                           (uint64_t *)t3, (uint64_t *)t3,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Y3 = B * t1 = B * C^3 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)b,
                                      (uint64_t *)t1, out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Y3 = t3 - Y3 = D(AC^2 - X3) - B * C^3 */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)t3,
                                          out->y, out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }
    }

    return (SCL_OK);
}

int32_t soft_ecc_double_jacobian(const metal_scl_t *const scl,
                                 const ecc_curve_t *const curve_params,
                                 const ecc_bignum_jacobian_point_t *const in,
                                 ecc_bignum_jacobian_point_t *const out,
                                 size_t nb_32b_words)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == in) ||
        (NULL == out))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == in->x) || (NULL == in->y) || (NULL == in->z) ||
        (NULL == out->x) || (NULL == out->y) || (NULL == out->z))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->bignum_func.set_modulus) ||
        (NULL == scl->bignum_func.mod_square) ||
        (NULL == scl->bignum_func.mod_add) ||
        (NULL == scl->bignum_func.mod_sub) ||
        (NULL == scl->bignum_func.mod_mult))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    /* check length consistency */
    if (nb_32b_words != curve_params->curve_wsize)
    {
        return (SCL_INVALID_LENGTH);
    }

    result = soft_ecc_infinite_jacobian(scl, in, nb_32b_words);
    if (SCL_OK > result)
    {
        return (result);
    }
    else if (false != result)
    {
        // return(x2:y2:0)
        memcpy(out->x, in->x, nb_32b_words * sizeof(uint32_t));
        memcpy(out->y, in->y, nb_32b_words * sizeof(uint32_t));
        memset(out->z, 0, nb_32b_words * sizeof(uint32_t));

        // soft_ecc_jacobian_copy(in, out, nb_32b_words);
        return (SCL_OK);
    }

    {
        uint32_t a[nb_32b_words] __attribute__((aligned(8)));
        uint32_t b[nb_32b_words] __attribute__((aligned(8)));
        uint32_t d[nb_32b_words] __attribute__((aligned(8)));
        uint32_t t1[nb_32b_words] __attribute__((aligned(8)));
        uint32_t t2[nb_32b_words] __attribute__((aligned(8)));

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* a = Y1^2 */
        result = scl->bignum_func.mod_square(scl, &bignum_ctx, in->y,
                                             (uint64_t *)a, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = 2 * A */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)a,
                                          (uint64_t *)a, (uint64_t *)t1,
                                          nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = 2 * t1 = 4*A */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)t1,
                                          (uint64_t *)t1, (uint64_t *)t1,
                                          nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* B = t1 * X1 = 4 * A * X1 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t1,
                                           in->x, (uint64_t *)b, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* d = 2 * X1 */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, in->x, in->x,
                                          (uint64_t *)d, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* d = d + X1 = 3* X1*/
        result =
            scl->bignum_func.mod_add(scl, &bignum_ctx, in->x, (uint64_t *)d,
                                     (uint64_t *)d, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* d = d * X1 = 3* X1^2 */
        result =
            scl->bignum_func.mod_mult(scl, &bignum_ctx, in->x, (uint64_t *)d,
                                      (uint64_t *)d, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t2 = Z1 * Z1 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, in->z, in->z,
                                           (uint64_t *)t2, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t2 = t2 * t2 = Z1^4 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t2,
                                           (uint64_t *)t2, (uint64_t *)t2,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t2 = a(curve param) * t2 = a(curve param) * Z1^4 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, curve_params->a,
                                           (uint64_t *)t2, (uint64_t *)t2,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* d = d + t2 = 3* X1^2 + a(curve param) * Z1^4 */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)t2,
                                          (uint64_t *)d, (uint64_t *)d,
                                          nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t2 = d^2 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)d,
                                           (uint64_t *)d, (uint64_t *)t2,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Z3 = Y1 * Z1 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, in->y, in->z,
                                           out->z, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Z3 = 2 * Z3 = 2 * Y1 * Z1 */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, out->z, out->z,
                                          out->z, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* X3 = 2 * B */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)b,
                                          (uint64_t *)b, out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* X3 = t2 - X3 = d^2 - 2*b */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)t2,
                                          out->x, out->x, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = 2 * t1 = 8*A */
        result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)t1,
                                          (uint64_t *)t1, (uint64_t *)t1,
                                          nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* t1 = t1 * A = 8*A^2 */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t1,
                                           (uint64_t *)a, (uint64_t *)t1,
                                           nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Y3 = B - X3 */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, (uint64_t *)b,
                                          out->x, out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Y3 = D * Y3 = D * (B - X3) */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)d,
                                           out->y, out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* Y3 = Y3 - t1 = D * (B - X3) - 8*A^2 */
        result = scl->bignum_func.mod_sub(scl, &bignum_ctx, out->y,
                                          (uint64_t *)t1, out->y, nb_32b_words);
        if (SCL_OK > result)
        {
            return (result);
        }
    }

    return (SCL_OK);
}

size_t soft_ecc_bit_extract(const uint32_t *const array, size_t bit_idx)
{

    if (array[bit_idx / (sizeof(uint32_t) * __CHAR_BIT__)] &
        ((uint32_t)1 << ((uint32_t)(bit_idx %
                                    (sizeof(uint32_t) * __CHAR_BIT__)))))
    {
        return (1);
    }
    else
    {
        return (0);
    }
}

void soft_ecc_set_msbit_curve(uint32_t *const array, size_t *const array_size,
                              size_t np, size_t words_tmp,
                              const ecc_curve_t *const curve_params)
{
    /**
     * if the P msb position is not at the word type msb position
     * we can use the same word for setting the msb
     */
    if ((curve_params->p[words_tmp - 1] >>
         (sizeof(uint32_t) * __CHAR_BIT__ - 1)) == 0)
    {
        array[curve_params->curve_wsize - 1] +=
            (uint32_t)(1 << (np % (sizeof(uint32_t) * __CHAR_BIT__)));
        *array_size = (uint32_t)curve_params->curve_wsize;
    }
    else
    /**
     * but if the curve P msb position is max in the word type, we need to add
     * the extra 1 bit in a new word
     */
    {
        array[curve_params->curve_wsize] = 1;
        *array_size = (uint32_t)curve_params->curve_wsize + 1;
    }
}

void soft_ecc_msbit_and_size(size_t *const msb, size_t *const msw,
                             const ecc_curve_t *const curve_params)
{
    /* theoretical position of the msb */
    *msb = curve_params->curve_wsize * sizeof(uint32_t) * __CHAR_BIT__;
    /* theoretical position of the msw */
    *msw = curve_params->curve_wsize;
    /* 1-search the highest non null word in curve n */
    while (curve_params->n[*msw - 1] == 0)
    {
        (*msw)--;
        (*msb) -= sizeof(uint32_t) * __CHAR_BIT__;
    }
    /* 2-in this msw, look for the msb */
    while ((*msb > 0) &&
           (soft_ecc_bit_extract((const uint32_t *)curve_params->n,
                                 (*msb) - 1) == 0))
    {
        (*msb)--;
    }
}

int32_t soft_ecc_xycz_add(const metal_scl_t *const scl,
                          const ecc_curve_t *const curve_params,
                          const ecc_bignum_affine_point_t *const in1,
                          const ecc_bignum_affine_point_t *const in2,
                          ecc_bignum_affine_point_t *const out1,
                          ecc_bignum_affine_point_t *const out2)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == in1) ||
        (NULL == in2) || (NULL == out1) || (NULL == out2))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == in1->x) || (NULL == in1->y) || (NULL == in2->x) ||
        (NULL == in2->y) || (NULL == out1->x) || (NULL == out1->y) ||
        (NULL == out2->x) || (NULL == out2->y))
    {
        return (SCL_INVALID_INPUT);
    }

    {
        uint32_t t1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t2[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t3[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t4[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t5[curve_params->curve_wsize] __attribute__((aligned(8)));

        memcpy(t1, in1->x, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(t2, in1->y, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(t3, in2->x, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(t4, in2->y, curve_params->curve_wsize * sizeof(uint32_t));

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 1. t5 = t3 - t1 = X2 - X1 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t1,
            (uint64_t *)t5, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 2. t5 = t5^2 = (X2 - X1)^2 = A */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t5, (uint64_t *)t5,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 3. t1 = t1 * t5 = X1 * A = B */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t1, (const uint64_t *)t5,
            (uint64_t *)t1, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 4. t3 = t3 * t5 = X2*A = C */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t5,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 5. t4 =  t4 - t2 = Y2 - Y1 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t2,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 6. t5 = t4^2 = (Y2 - Y1)^2 = D */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t4, (uint64_t *)t5,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 7. t5 = t5 - t1 = D - B */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t5, (const uint64_t *)t1,
            (uint64_t *)t5, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 8. t5 = t5 - t3 = X3 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t5, (const uint64_t *)t3,
            (uint64_t *)t5, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 9. t3 = t3 - t1 = C - B */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t1,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 10. t2 = t2 * t3 = Y1 * (C - B) */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t2, (const uint64_t *)t3,
            (uint64_t *)t2, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 11. t3 = t1 - t5 = B - X3 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t1, (const uint64_t *)t5,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 12. t4 = t4 * t3 = (Y2 - Y1) * (B - X3) */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t3,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 13. t4 = t4 - t2 = Y3 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t2,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        memcpy(out1->x, t5, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out1->y, t4, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out2->x, t1, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out2->y, t2, curve_params->curve_wsize * sizeof(uint32_t));
    }

    return (SCL_OK);
}

int32_t soft_ecc_xycz_addc(const metal_scl_t *const scl,
                           const ecc_curve_t *const curve_params,
                           const ecc_bignum_affine_point_t *const in1,
                           const ecc_bignum_affine_point_t *const in2,
                           ecc_bignum_affine_point_t *const out1,
                           ecc_bignum_affine_point_t *const out2)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == in1) ||
        (NULL == in2) || (NULL == out1) || (NULL == out2))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == in1->x) || (NULL == in1->y) || (NULL == in2->x) ||
        (NULL == in2->y) || (NULL == out1->x) || (NULL == out1->y) ||
        (NULL == out2->x) || (NULL == out2->y))
    {
        return (SCL_INVALID_INPUT);
    }

    {
        uint32_t t1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t2[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t3[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t4[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t5[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t6[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t7[curve_params->curve_wsize] __attribute__((aligned(8)));

        memcpy(t1, in1->x, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(t2, in1->y, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(t3, in2->x, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(t4, in2->y, curve_params->curve_wsize * sizeof(uint32_t));

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 1. t5 = t3 - t1 = X2 - X1 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t1,
            (uint64_t *)t5, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 2. t5 = t5^2 = (X2 - X1)^2 = A */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t5, (uint64_t *)t5,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 3. t1 = t1 * t5 = X1 * A = B */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t1, (const uint64_t *)t5,
            (uint64_t *)t1, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 4. t3 = t3 * t5 = X2 * A = C */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t5,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 5. t5 = t4 + t2 = Y1 + Y2 */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t2,
            (uint64_t *)t5, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 6. t4 = t4 - t2 = Y1 - Y2 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t2,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 7. t6 = t3 - t1 = C - B */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t1,
            (uint64_t *)t6, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 8. t2 = t2 * t6 = Y1 * (C - B) */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t2, (const uint64_t *)t6,
            (uint64_t *)t2, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 9. t6 = t3 + t1 = B + C */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t1,
            (uint64_t *)t6, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 10. t3 = t4^2 = (Y2 - Y1)^2 */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t4, (uint64_t *)t3,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 11. t3 = t3 - t6 = X3 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t6,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 12. t7 = t1 - t3 = B - X3 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t1, (const uint64_t *)t3,
            (uint64_t *)t7, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 13. t4 = t4 * t7 = (Y1 - Y2)(B - X3) */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t7,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 14. t4 = t4 - t2 = Y3 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t2,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 15. t7 = t5^2 = (Y2 + Y1)^2 = F */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t5, (uint64_t *)t7,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 16. t7 = t7 - t6 = X3' */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t7, (const uint64_t *)t6,
            (uint64_t *)t7, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 17. t6 = t7 - t1 = X3' - B */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t7, (const uint64_t *)t1,
            (uint64_t *)t6, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 18. t6 = t6 * t5 = (Y1 + Y2)(X3' - B) */
        result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)t6,
                                           (uint64_t *)t5, (uint64_t *)t6,
                                           curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 19. t6 = t6 - t2 = Y3' */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t6, (const uint64_t *)t2,
            (uint64_t *)t6, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        memcpy(out1->x, t3, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out1->y, t4, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out2->x, t7, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out2->y, t6, curve_params->curve_wsize * sizeof(uint32_t));
    }

    return (SCL_OK);
}

int32_t soft_ecc_xycz_idbl(const metal_scl_t *const scl,
                           const ecc_curve_t *const curve_params,
                           const ecc_bignum_affine_point_t *const in,
                           ecc_bignum_affine_point_t *const out1,
                           ecc_bignum_affine_point_t *const out2)
{
    int32_t result;
    bignum_ctx_t bignum_ctx;

    if ((NULL == scl) || (NULL == curve_params) || (NULL == in) ||
        (NULL == out1) || (NULL == out2))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == in->x) || (NULL == in->y) || (NULL == out1->x) ||
        (NULL == out1->y) || (NULL == out2->x) || (NULL == out2->y))
    {
        return (SCL_INVALID_INPUT);
    }

    {
        uint32_t t1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t2[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t3[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t4[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t5[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t t6[curve_params->curve_wsize] __attribute__((aligned(8)));

        memcpy(t1, in->x, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(t2, in->y, curve_params->curve_wsize * sizeof(uint32_t));

        result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                              curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 1. t3 = t1^2 = x1^2 */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t1, (uint64_t *)t3,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 2. t4 = 2 * t3 = 2 * x1^2 */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t3,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 3. t3 = t3 + t4 = 3 * x1^2 */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t4,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 4. t3 = t3 + a(curve_param) = 3 * x1^2 + a(curve_param) = B */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t3, curve_params->a,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 5. t4 = t2^2 = y1^2 */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t2, (uint64_t *)t4,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 6. t4 = 2 * t4 = 2 * y1^2 */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t4,
            (uint64_t *)t4, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 7. t5 = 2 * t4 = 4 * y1^2 */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t4, (const uint64_t *)t4,
            (uint64_t *)t5, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 8. t5 = t5 * t1 = 4 * x1 * y1^2 = X1' = A */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t1, (const uint64_t *)t5,
            (uint64_t *)t5, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 9. t6 = t3^2 = B^2 */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t3, (uint64_t *)t6,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 10. t6 = t6 - t5 = B^2 - A */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t6, (const uint64_t *)t5,
            (uint64_t *)t6, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 11. t6 = t6 - t5 = X2 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t6, (const uint64_t *)t5,
            (uint64_t *)t6, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 12. t1 = t5 - t6 = A - X2 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t5, (const uint64_t *)t6,
            (uint64_t *)t1, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 13. t1 = t1 * t3 = B * (A - X2) */
        result = scl->bignum_func.mod_mult(
            scl, &bignum_ctx, (const uint64_t *)t1, (const uint64_t *)t3,
            (uint64_t *)t1, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 14. t3 = t4^2 = 4*y1^4 */
        result = scl->bignum_func.mod_square(
            scl, &bignum_ctx, (const uint64_t *)t4, (uint64_t *)t3,
            curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 15. t3 = 2 * t3 = 8 * y1^4 = Y1' */
        result = scl->bignum_func.mod_add(
            scl, &bignum_ctx, (const uint64_t *)t3, (const uint64_t *)t3,
            (uint64_t *)t3, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 16. t1 = t1 - t3 = Y2 */
        result = scl->bignum_func.mod_sub(
            scl, &bignum_ctx, (const uint64_t *)t1, (const uint64_t *)t3,
            (uint64_t *)t1, curve_params->curve_wsize);
        if (SCL_OK > result)
        {
            return (result);
        }

        memcpy(out1->x, t6, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out1->y, t1, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out2->x, t5, curve_params->curve_wsize * sizeof(uint32_t));
        memcpy(out2->y, t3, curve_params->curve_wsize * sizeof(uint32_t));
    }
    return (SCL_OK);
}

int32_t soft_ecc_mult_coz(const metal_scl_t *const scl,
                          const ecc_curve_t *const curve_params,
                          const ecc_bignum_affine_point_t *const point,
                          const uint64_t *const k, size_t k_nb_32bits_words,
                          ecc_bignum_affine_point_t *const q)
{
    int32_t result;
    size_t i, n, b;
    bignum_ctx_t bignum_ctx;
    ecc_bignum_affine_point_t p[2];

    if ((NULL == scl) || (NULL == curve_params) || (NULL == q) || (NULL == k) ||
        (NULL == point))
    {
        return (SCL_INVALID_INPUT);
    }

    uint32_t xr_0[curve_params->curve_wsize] __attribute__((aligned(8)));
    uint32_t yr_0[curve_params->curve_wsize] __attribute__((aligned(8)));
    uint32_t xr_1[curve_params->curve_wsize] __attribute__((aligned(8)));
    uint32_t yr_1[curve_params->curve_wsize] __attribute__((aligned(8)));
    uint32_t lambda[curve_params->curve_wsize] __attribute__((aligned(8)));
    uint32_t lambda2[curve_params->curve_wsize] __attribute__((aligned(8)));

    /* 1. xycz-idbl */
    p[0].x = (uint64_t *)xr_0;
    p[0].y = (uint64_t *)yr_0;
    p[1].x = (uint64_t *)xr_1;
    p[1].y = (uint64_t *)yr_1;

    result = soft_ecc_xycz_idbl(scl, curve_params, point, &p[1], &p[0]);
    if (SCL_OK > result)
    {
        return (result);
    }

    /* 2.for i=n-2 downto 1 do */
    n = k_nb_32bits_words * sizeof(uint32_t) * 8;

    while ((n > 0) && (soft_ecc_bit_extract((const uint32_t *)k, n - 1) == 0))
    {
        n--;
    }

    for (i = n - 2; i >= 1; i--)
    {
        /* 3. b=k_i */
        b = soft_ecc_bit_extract((const uint32_t *)k, i);

        /* 4.(r1-b,rb)=xycz-addc(rb,r1-b) */
        result = soft_ecc_xycz_addc(scl, curve_params, &p[b], &p[1 - b],
                                    &p[1 - b], &p[b]);
        if (SCL_OK > result)
        {
            return (result);
        }

        /* 5.(rb,r1-b)=xycz-add(r1-b,rb) */
        result = soft_ecc_xycz_add(scl, curve_params, &p[1 - b], &p[b], &p[b],
                                   &p[1 - b]);
        if (SCL_OK > result)
        {
            return (result);
        }
    }

    /* 7. b=k0 */
    b = k[0] & 1;

    /* 8. (r1-b,rb)=xycz-addc(rb,r1-b) */
    result = soft_ecc_xycz_addc(scl, curve_params, &p[b], &p[1 - b], &p[1 - b],
                                &p[b]);
    if (SCL_OK > result)
    {
        return (result);
    }

    result = scl->bignum_func.set_modulus(scl, &bignum_ctx, curve_params->p,
                                          curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    /* 9. lambda=finallnvz(r0,r1,p,b); */
    result =
        scl->bignum_func.mod_sub(scl, &bignum_ctx, p[1].x, p[0].x,
                                 (uint64_t *)lambda, curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda,
                                       p[b].y, (uint64_t *)lambda,
                                       curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda,
                                       point->x, (uint64_t *)lambda,
                                       curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    result =
        scl->bignum_func.mod_inv(scl, &bignum_ctx, (uint64_t *)lambda,
                                 (uint64_t *)lambda, curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda,
                                       point->y, (uint64_t *)lambda,
                                       curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda,
                                       p[b].x, (uint64_t *)lambda,
                                       curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    /* 10. (rb,r1-b)=xycz-add(r1-b,rb) */
    result = soft_ecc_xycz_add(scl, curve_params, &p[1 - b], &p[b], &p[b],
                               &p[1 - b]);
    if (SCL_OK > result)
    {
        return (result);
    }

    /* 11. return.. */
    /* x0.lambda */
    result = scl->bignum_func.mod_square(scl, &bignum_ctx, (uint64_t *)lambda,
                                         (uint64_t *)lambda2,
                                         curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda2,
                                       p[0].x, q->x, curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    /* y0.lambda */
    result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda,
                                       (uint64_t *)lambda2, (uint64_t *)lambda2,
                                       curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)lambda2,
                                       p[0].y, q->y, curve_params->curve_wsize);
    if (SCL_OK > result)
    {
        return (result);
    }

    return (SCL_OK);
}

/**
 * Modular Arthmetic optimized for ecc
 */

int32_t soft_ecc_mod_secp384r1(const metal_scl_t *const scl,
                               const uint64_t *const in, size_t in_nb_32b_words,
                               const uint64_t *const modulus,
                               size_t modulus_nb_32b_words,
                               uint64_t *const remainder)
{
    int32_t result = 0;
    int32_t carry = 0;

    const uint32_t *in32 = (const uint32_t *)in;

    /* NOTE: We use NIST.FIPS 186-4 notation */
    uint32_t a[ECC_SECP384R1_32B_WORDS_SIZE * 2] __attribute__((aligned(8)));
    uint32_t s[ECC_SECP384R1_32B_WORDS_SIZE] __attribute__((aligned(8)));

    size_t i;

    if ((NULL == scl) || (NULL == in) || (NULL == modulus) ||
        (NULL == remainder))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->bignum_func.sub) || (NULL == scl->bignum_func.add))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    /* output should be modulus size */
    if ((in_nb_32b_words > ECC_SECP384R1_32B_WORDS_SIZE * 2) &&
        (modulus_nb_32b_words != ECC_SECP384R1_32B_WORDS_SIZE))
    {
        return (SCL_INVALID_LENGTH);
    }

    /**
     * We use an intermediate buffer here instead of using direcly in buffer and
     * branching to manage length
     */
    for (i = 0; i < in_nb_32b_words; i++)
    {
        a[i] = in32[i];
    }

    for (; i < ECC_SECP384R1_32B_WORDS_SIZE * 2; i++)
    {
        a[i] = 0;
    }

    /* s2 */
    for (i = 0; i < ECC_SECP384R1_32B_WORDS_SIZE; i++)
    {
        s[i] = a[i + 12];
    }

    result = scl->bignum_func.add(scl, (uint64_t *)a, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry = result;

    /* s3 */
    s[0] = a[21];
    s[1] = a[22];
    s[2] = a[23];
    /* s3..s11=a12..a20 */
    for (i = 3; i < ECC_SECP384R1_32B_WORDS_SIZE; i++)
    {
        s[i] = a[i + 9];
    }

    result = scl->bignum_func.add(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry += result;

    /* s4 */
    s[0] = 0;
    s[1] = a[23];
    s[2] = 0;
    s[3] = a[20];

    for (i = 4; i < ECC_SECP384R1_32B_WORDS_SIZE; i++)
    {
        s[i] = a[8 + i];
    }

    result = scl->bignum_func.add(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry += result;

    /* s1 */
    memset(s, 0, sizeof(s));
    s[4] = a[21];
    s[5] = a[22];
    s[6] = a[23];

    /* 2 * s1 */
    result = scl->bignum_func.add(scl, (uint64_t *)s, (uint64_t *)s,
                                  (uint64_t *)s, ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry += result;

    /* 2 * s1 + previous */
    result = scl->bignum_func.add(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry += result;

    /* s5 */
    s[4] = a[20];
    s[5] = a[21];
    s[6] = a[22];
    s[7] = a[23];

    result = scl->bignum_func.add(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry += result;

    /* s6 */
    s[0] = a[20];
    s[3] = a[21];
    s[4] = a[22];
    s[5] = a[23];
    s[6] = 0;
    s[7] = 0;

    result = scl->bignum_func.add(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry += result;

    /* d2 (computed now because very close to s6 */
    s[0] = 0;
    s[1] = a[20];
    s[2] = a[21];
    s[3] = a[22];
    s[4] = a[23];
    s[5] = 0;

    result = scl->bignum_func.sub(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry -= result;

    /*  d3 (computed now because very close to d2) */
    s[1] = 0;
    s[2] = 0;
    s[3] = a[23];

    result = scl->bignum_func.sub(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry -= result;

    /* d1 */
    s[0] = a[23];
    for (i = 1; i < ECC_SECP384R1_32B_WORDS_SIZE; i++)
    {
        s[i] = a[i + 11];
    }

    result = scl->bignum_func.sub(scl, remainder, (uint64_t *)s, remainder,
                                  ECC_SECP384R1_32B_WORDS_SIZE);
    if (SCL_OK > result)
    {
        return (result);
    }

    carry -= result;

    if (carry < 0)
    {
        while (carry < 0)
        {
            result = scl->bignum_func.add(scl, remainder, modulus, remainder,
                                          ECC_SECP384R1_32B_WORDS_SIZE);
            if (SCL_OK > result)
            {
                return (result);
            }

            carry += result;
        }
    }
    else
    {
        while ((carry != 0) ||
               (0 < scl->bignum_func.compare(scl, remainder, modulus,
                                             ECC_SECP384R1_32B_WORDS_SIZE)))
        {
            result = scl->bignum_func.sub(scl, remainder, modulus, remainder,
                                          ECC_SECP384R1_32B_WORDS_SIZE);
            if (SCL_OK > result)
            {
                return (result);
            }

            carry -= result;
        }
    }

    return (result);
}

int32_t soft_ecc_mod(const metal_scl_t *const scl, const uint64_t *const in,
                     size_t in_nb_32b_words, const uint64_t *const modulus,
                     size_t modulus_nb_32b_words, uint64_t *const remainder)
{
    int32_t result = 0;

    if ((NULL == scl) || (NULL == in) || (NULL == ecc_secp384r1.square_p))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == scl->bignum_func.compare_len_diff))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    // if ((ecc_p_p256r1 == modulus) && (ECC_SECP256R1_32B_WORDS_SIZE ==
    // modulus_nb_32b_words))
    // {

    // }
    // else if ((ecc_p_p384r1 == modulus) && (ECC_SECP384R1_32B_WORDS_SIZE ==
    // modulus_nb_32b_words))
    // {

    // }
    // else if ((ecc_p_p521r1 == modulus) && (ECC_SECP521R1_32B_WORDS_SIZE ==
    // modulus_nb_32b_words))
    // {

    // }

    if ((ecc_secp384r1.p == modulus) &&
        (ECC_SECP384R1_32B_WORDS_SIZE == modulus_nb_32b_words))
    {
        result = scl->bignum_func.compare_len_diff(
            scl, in, in_nb_32b_words, ecc_secp384r1.square_p,
            ECC_SECP384R1_32B_WORDS_SIZE * 2);
        if (0 <= result)
        {
            return (SCL_ERROR);
        }

        result = soft_ecc_mod_secp384r1(scl, in, in_nb_32b_words, modulus,
                                        modulus_nb_32b_words, remainder);
    }
    else
    {
        result = soft_bignum_mod(scl, in, in_nb_32b_words, modulus,
                                 modulus_nb_32b_words, remainder);
    }

    return (result);
}
