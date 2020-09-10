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

int32_t soft_ecdsa_signature(const metal_scl_t *const scl,
                             const ecc_curve_t *const curve_params,
                             const uint8_t *const priv_key,
                             ecc_signature_t *const signature,
                             const uint8_t *const hash, size_t hash_len)
{
    int32_t result, result_2;
    size_t nbbits;
    size_t i;
    ecc_bignum_affine_point_t mp;
    ecc_bignum_affine_point_t q;
    bignum_ctx_t bignum_ctx;

    size_t msb, msw, ext_k_size;

    if ((NULL == scl) || (NULL == priv_key) || (NULL == signature) ||
        (NULL == hash) || (NULL == curve_params))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((NULL == signature->r) || (NULL == signature->s) ||
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

    if ((NULL == scl->trng_func.get_data) ||
        (NULL == scl->bignum_func.is_null) || (NULL == scl->bignum_func.mod) ||
        (NULL == scl->bignum_func.compare) ||
        (NULL == scl->bignum_func.set_modulus))
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    {
        /* we use the steps and the identifiers defined in algo 4.29 in GtECC */

        uint32_t r[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t s[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t e[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t u1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t x1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t y1[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t x2[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t y2[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t w[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t d[curve_params->curve_wsize] __attribute__((aligned(8)));
        uint32_t k[curve_params->curve_wsize] __attribute__((aligned(8)));
        /* ext_k is curve_wsize + 1 ! */
        uint32_t ext_k[curve_params->curve_wsize + 1]
            __attribute__((aligned(8)));

        do
        {
            /* determine the n msW */
            soft_ecc_msbit_and_size(&msb, &msw, curve_params);
            /* determine the msb position in the n msW */
            nbbits = (msb - 1) % (sizeof(uint32_t) * __CHAR_BIT__);
            if (0 == nbbits)
            {
                nbbits = (sizeof(uint32_t) * __CHAR_BIT__);
            }

            /* 3. randomly generate k [1,k-1] */
            do
            {
                for (i = 0; i < curve_params->curve_wsize; i++)
                {
                    result = scl->trng_func.get_data(scl, &k[i]);
                    if (SCL_OK != result)
                    {
                        goto cleanup;
                    }
                }

                truncate_array((uint8_t *)k,
                               curve_params->curve_wsize * sizeof(uint32_t),
                               curve_params->curve_bitsize);

                result = scl->bignum_func.compare(scl, (uint64_t *)k,
                                                  curve_params->n,
                                                  curve_params->curve_wsize);

                result_2 =
                    scl->bignum_func.is_null(scl, k, curve_params->curve_wsize);

            }
            /**
             * As a modular reduction is not protected against SCA, we prefer to
             * loop until the generated value is correct the accepted range is
             * between 1 and n-1
             */
            while ((result >= 0) || (false != result_2));

            /* 4 (x1,y1)=k.G */
            q.x = (uint64_t *)x1;
            q.y = (uint64_t *)y1;
            // p.x = curve_params->xg;
            // p.y = curve_params->yg;

            /**
             * algorithm for k protection
             * the lattice attack is about guessing the k Msb position
             * our countermeasure is then creating a "fake" Msb, i.e. forcing to
             * 1 a bit at a fixed position (so the bit can not be guessed :-) ),
             * beyond the real Msb of k, then computing the product of this new
             * value times p, then removing the contribution of this fake extra
             * 1-bit, so: 4.1-compute (1|k).p, this new, extended k is named
             * ext_k, its size being ext_k_size 4.2-compute (1|0...0).P; in
             * fact, use precomputed values 4.3-substract (2) to (1) the result
             * will then be (1|k).P-(1|0..0).P => k.P <=> (1|k).P+(-(1|0..0).P)
             */

            /**
             * let's start !
             * 4.1 compute the extended scalar,i.e. scalar with a leading 1
             * so, determine the k msb and the k msw
             * depending on the curve, this value may require a new word
             * a. determine the n msb position
             */

            soft_ecc_msbit_and_size(&msb, &msw, curve_params);
            /* b. prepare the new,extended value from k, aligned on n */
            memcpy(ext_k, k, curve_params->curve_wsize * sizeof(uint32_t));
            ext_k[curve_params->curve_wsize] = 0;
            soft_ecc_set_msbit_curve(ext_k, &ext_k_size, msb, msw,
                                     curve_params);

            /* 4.1-compute (1|k).P, i.e. (ext_k).P, using coZ routines */
            result = scl->bignum_func.set_modulus(
                scl, &bignum_ctx, curve_params->p, curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                return (result);
            }

            result = soft_ecc_mult_coz(scl, curve_params, curve_params->g,
                                       (uint64_t *)ext_k, ext_k_size, &q);
            if (SCL_OK != result)
            {
                goto cleanup;
            }
            mp.x = (uint64_t *)x2;
            mp.y = (uint64_t *)y2;

            /**
             * 4.2-compute or copy (1|0..0).P
             * the curve params should contain precomputed_1_x and
             * precomputed_1_y that correspond to -(1|0).P, if available !
             * (should always be available except for size-constrained
             * platforms)
             */
            if (NULL != curve_params->precomputed_1_x &&
                NULL != curve_params->precomputed_1_y)
            {
                memcpy(x2, curve_params->precomputed_1_x,
                       curve_params->curve_wsize * sizeof(uint32_t));
                memcpy(y2, curve_params->precomputed_1_y,
                       curve_params->curve_wsize * sizeof(uint32_t));
            }
            else
            {
                /* very time consuming but usually not performed */
                memset(ext_k, 0, sizeof(ext_k));
                soft_ecc_set_msbit_curve(ext_k, &ext_k_size, msb, msw,
                                         curve_params);
                result = soft_ecc_mult_coz(scl, curve_params, curve_params->g,
                                           (uint64_t *)ext_k, ext_k_size, &mp);
                if (SCL_OK != result)
                {
                    goto cleanup;
                }

                /* compute the opposite:  -(x2,y2)=(x2,-y2) and y2=p-y2=-y2 */
                result = scl->bignum_func.mod_sub(
                    scl, &bignum_ctx, curve_params->p, (uint64_t *)y2,
                    (uint64_t *)y2, curve_params->curve_wsize);
                if (SCL_OK != result)
                {
                    goto cleanup;
                }
            }
            /* 4.3 (1|k).P+ (-(1|0..0).P) */
            result = soft_ecc_add_affine_affine(scl, curve_params, &q, &mp, &q,
                                                curve_params->curve_wsize);

            if (SCL_OK != result)
            {
                goto cleanup;
            }
            /* 5. compute r = x1 mod n = q.x mod n */
            result = scl->bignum_func.mod(
                scl, q.x, curve_params->curve_wsize, curve_params->n,
                curve_params->curve_wsize, (uint64_t *)r);
            if (SCL_OK != result)
            {
                goto cleanup;
            }

            /* store in signature r */
            copy_swap_array(signature->r, (uint8_t *)r,
                            curve_params->curve_bsize);

            /**
             * algorithm for d protection
             * 6. s=k^(-1).(h+r.d) mod n
             * we want to hide the use of d,the secret, by using masks
             * we have a multiplicative mask, m1 and an additive mask, m2
             * s=k^(-1).(h+r.d) mod n
             * is equivalent to
             * s=k^(-1).(h+r.(n+d)) mod n
             * equivalent to (add and substract m2, multiply and divide by m1)
             * s=r.m1.(h/r   +(n-m2) + (d+m2)) /(m1.k)
             * equivalent to
             * S=r.m1.(h.r^(-1) +(n-m2) + (d+m2)) .(m1.k)^(-1)
             * we now develop the expression to have m1 everywhere and still
             * masking when m2 is not masking s=r.(m1.h/r + m1.(n-m2) +
             * m1.(d+m2))/(m1.k) s=r.(t1.h.r^(-1)+ m1.(n-m2) +
             * m1.(d+m2)).(m1.k)^(-1)
             */

            /**
             * so the sequence of computation is the following
             * 6.1 generate m1 and m2
             * 6.2  compute r^(-1)
             * 6.3a h.r^(-1)
             * 6.3b m1.h.r^(-1)
             * 6.4a (n-m2)
             * 6.4b m1.(n-m2)
             * 6.5  m1.h.r^(-1) +m1.(n-m2)
             * 6.6a d+m2
             * 6.6b m1.(d+m2)
             * 6.7  m1.h.r^(-1) +m1.(n-m2)+m1.(d+m2)
             * 6.8a m1.k
             * 6.8b (m1.k)^(-1)
             * 6.9  final computation
             */

            /**
             * x1 is used for m1,random multiplicative mask, y1 for m2, random
             * additive mask
             * x1 not used anymore so free to use
             * generate random number x1
             * 6.1 m1=x1
             */
            memset(x1, 0, sizeof(x1));
            do
            {
                for (i = 0; i < msw; i++)
                {
                    result = scl->trng_func.get_data(scl, &x1[i]);
                }

                truncate_array((uint8_t *)x1,
                               curve_params->curve_wsize * sizeof(uint32_t),
                               nbbits);

                result = scl->bignum_func.compare(scl, (uint64_t *)x1,
                                                  curve_params->n,
                                                  curve_params->curve_wsize);

                result_2 = scl->bignum_func.is_null(scl, x1,
                                                    curve_params->curve_wsize);

            }

            /**
             * As a modular reduction is not protected against SCA, we prefer to
             * loop until the generated value is correct the accepted range is
             * between 1 and n-1
             */
            while ((result >= 0) || (false != result_2));

            /**
             * generate random number y1
             * m2=y1
             */
            memset(y1, 0, sizeof(x1));
            do
            {
                for (i = 0; i < msw; i++)
                {
                    result = scl->trng_func.get_data(scl, &y1[i]);
                }

                truncate_array((uint8_t *)y1,
                               curve_params->curve_wsize * sizeof(uint32_t),
                               nbbits);

                result = scl->bignum_func.compare(scl, (uint64_t *)y1,
                                                  curve_params->n,
                                                  curve_params->curve_wsize);

                result_2 = scl->bignum_func.is_null(scl, y1,
                                                    curve_params->curve_wsize);

            }

            /**
             * As a modular reduction is not protected against SCA, we prefer to
             * loop until the generated value is correct the accepted range is
             * between 1 and n-1
             */
            while ((result >= 0) || (false != result_2));

            result = scl->bignum_func.set_modulus(
                scl, &bignum_ctx, curve_params->n, curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                return (result);
            }

            /* 6.2 inverting r (r is public so no need for masking) */
            result = scl->bignum_func.mod_inv(scl, &bignum_ctx, (uint64_t *)r,
                                              (uint64_t *)w,
                                              curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                return (result);
            }

            /* 6.3a h.r^(-1) */
            memset(e, 0, sizeof(e));

            copy_swap_array(
                (uint8_t *)e, hash,
                MIN(hash_len, curve_params->curve_wsize * sizeof(uint32_t)));

            result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)w,
                                               (uint64_t *)e, (uint64_t *)w,
                                               curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.3b m1.h.r^(-1) so x1.w */
            result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)w,
                                               (uint64_t *)x1, (uint64_t *)w,
                                               curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* prepare masking for d */
            /* 6.4a n-y1 (=n-m2) */
            result = scl->bignum_func.mod_sub(scl, &bignum_ctx, curve_params->n,
                                              (uint64_t *)y1, (uint64_t *)u1,
                                              curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.4b. m1.(n-m2)=x1.(n-y1) */
            result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)u1,
                                               (uint64_t *)x1, (uint64_t *)u1,
                                               curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.5 x1.h.r^(-1) + x1.(n-y1) */
            result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)w,
                                              (uint64_t *)u1, (uint64_t *)w,
                                              curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.6a d+m2 (=d+y1) */
            copy_swap_array((uint8_t *)d, priv_key,
                            curve_params->curve_wsize * sizeof(uint32_t));

            result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)d,
                                              (uint64_t *)y1, (uint64_t *)u1,
                                              curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.6b m1.(d+m2) (=x1.(d+y1)) */
            result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)u1,
                                               (uint64_t *)x1, (uint64_t *)u1,
                                               curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.7 +m1.(d+m2) */
            result = scl->bignum_func.mod_add(scl, &bignum_ctx, (uint64_t *)w,
                                              (uint64_t *)u1, (uint64_t *)w,
                                              curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.8a. masking k: m1.k (=x1.k) */
            result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)x1,
                                               (uint64_t *)k, (uint64_t *)u1,
                                               curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.8b inverting masked k: (m1*k)^(-1) */
            result = scl->bignum_func.mod_inv(scl, &bignum_ctx, (uint64_t *)u1,
                                              (uint64_t *)u1,
                                              curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.8 (m1.h.r^(-1)+m1.(n-m2)+m1.(d+m2)).(m1.k)^(-1)*/
            result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)w,
                                               (uint64_t *)u1, (uint64_t *)w,
                                               curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* 6.9 final computation */
            result = scl->bignum_func.mod_mult(scl, &bignum_ctx, (uint64_t *)w,
                                               (uint64_t *)r, (uint64_t *)s,
                                               curve_params->curve_wsize);
            if (SCL_OK > result)
            {
                goto cleanup;
            }

            /* check the signature is not null: 5. and 6. */
            result =
                scl->bignum_func.is_null(scl, s, curve_params->curve_wsize);

            result_2 =
                scl->bignum_func.is_null(scl, r, curve_params->curve_wsize);
        } while ((false != result) && (false != result_2));

        /* 6 result */
        copy_swap_array(signature->s, (uint8_t *)s, curve_params->curve_bsize);
    }

    result = SCL_OK;
cleanup:
    return (result);
}

int32_t soft_ecdsa_verification(const metal_scl_t *const scl,
                                const ecc_curve_t *const curve_params,
                                const ecc_affine_const_point_t *const pub_key,
                                const ecc_signature_t *const signature,
                                const uint8_t *const hash, size_t hash_len)
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
        (NULL == signature->r) || (NULL == signature->s) ||
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
        copy_swap_array((uint8_t *)r, signature->r, curve_params->curve_bsize);
        copy_swap_array((uint8_t *)s, signature->s, curve_params->curve_bsize);

        /* Check that r and s are in the interval [1, n-1] */
        result = scl->bignum_func.compare(scl, (uint64_t *)r, curve_params->n,
                                          curve_params->curve_wsize);
        if (result >= 0)
        {
            result = SCL_ERR_SIGNATURE;
            goto cleanup;
        }

        result = scl->bignum_func.compare(scl, (uint64_t *)s, curve_params->n,
                                          curve_params->curve_wsize);
        if (result >= 0)
        {
            result = SCL_ERR_SIGNATURE;
            goto cleanup;
        }

        result = scl->bignum_func.is_null(scl, r, curve_params->curve_wsize);
        if (false != result)
        {
            result = SCL_ERR_SIGNATURE;
            goto cleanup;
        }

        result = scl->bignum_func.is_null(scl, s, curve_params->curve_wsize);
        if (false != result)
        {
            result = SCL_ERR_SIGNATURE;
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
            result = SCL_ERR_SIGNATURE;
            goto cleanup;
        }
    }

    result = SCL_OK;
cleanup:
    return (result);
}
