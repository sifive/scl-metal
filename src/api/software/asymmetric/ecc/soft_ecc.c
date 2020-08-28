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

const ecc_curve_t ecc_secp256r1 = {ecc_a_p256r1,
                                   ecc_b_p256r1,
                                   ecc_p_p256r1,
                                   ecc_n_p256r1,
                                   &ecc_g_p256r1,
                                   ecc_inverse_2_p256r1,
                                   ecc_square_p_p256r1,
                                   ecc_precomputed_1_x_p256r1,
                                   ecc_precomputed_1_y_p256r1,
                                   ECC_SECP256R1_32B_WORDS_SIZE,
                                   ECC_SECP256R1_BYTESIZE,
                                   ECC_SECP256R1};

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

static const ecc_bignum_affine_point_t ecc_g_p384r1 = {ecc_xg_p384r1,
                                                       ecc_yg_p384r1};

const ecc_curve_t ecc_secp384r1 = {ecc_a_p384r1,
                                   ecc_b_p384r1,
                                   ecc_p_p384r1,
                                   ecc_n_p384r1,
                                   &ecc_g_p384r1,
                                   ecc_inverse_2_p384r1,
                                   NULL,
                                   ecc_precomputed_1_x_p384r1,
                                   ecc_precomputed_1_y_p384r1,
                                   ECC_SECP384R1_32B_WORDS_SIZE,
                                   ECC_SECP384R1_BYTESIZE,
                                   ECC_SECP384R1};

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

static const ecc_bignum_affine_point_t ecc_g_p521r1 = {ecc_xg_p521r1,
                                                       ecc_yg_p521r1};

const ecc_curve_t ecc_secp521r1 = {ecc_a_p521r1,
                                   ecc_b_p521r1,
                                   ecc_p_p521r1,
                                   ecc_n_p521r1,
                                   &ecc_g_p521r1,
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

size_t soft_ecc_bit_extract(uint32_t *array, size_t bit_idx)
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
