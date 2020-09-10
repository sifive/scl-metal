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
 * @file ecc.h
 * @brief Elliptic curve cryptography implementation/wrapper
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_BACKEND_ECC_H
#define SCL_BACKEND_ECC_H

#include <stddef.h>
#include <stdint.h>

/*! @brief size of curve SECP224R1 parameters in byte */
#define ECC_SECP224R1_BYTESIZE 28
/*! @brief size of curve SECP256R1 parameters in byte */
#define ECC_SECP256R1_BYTESIZE 32
/*! @brief size of curve SECP256K1 parameters in byte */
#define ECC_SECP256K1_BYTESIZE 32
/*! @brief size of curve BP256R1 parameters in byte */
#define ECC_BP256R1_BYTESIZE 32
/*! @brief size of curve SECP384R1 parameters in byte */
#define ECC_SECP384R1_BYTESIZE 48
/*! @brief size of curve SECP521R1 parameters in byte */
#define ECC_SECP521R1_BYTESIZE 66
/*! @brief size of curve BP384R1 parameters in byte */
#define ECC_BP384R1_BYTESIZE 48
/*! @brief size of curve BP512R1 parameters in byte */
#define ECC_BP512R1_BYTESIZE 64

/*! @brief size of curve SECP224R1 parameters in bits */
#define ECC_SECP224R1_BITSIZE 224
/*! @brief size of curve SECP256R1 parameters in bits */
#define ECC_SECP256R1_BITSIZE 256
/*! @brief size of curve SECP256K1 parameters in bits */
#define ECC_SECP256K1_BITSIZE 256
/*! @brief size of curve BP256R1 parameters in bits */
#define ECC_BP256R1_BITSIZE 256
/*! @brief size of curve SECP384R1 parameters in bits */
#define ECC_SECP384R1_BITSIZE 384
/*! @brief size of curve SECP521R1 parameters in bits */
#define ECC_SECP521R1_BITSIZE 521
/*! @brief size of curve BP384R1 parameters in bits */
#define ECC_BP384R1_BITSIZE 384
/*! @brief size of curve BP512R1 parameters in bits */
#define ECC_BP512R1_BITSIZE 512

/*! @brief number of 32bits word for curve SECP224R1 parameters */
#define ECC_SECP224R1_32B_WORDS_SIZE 8
/*! @brief number of 32bits word for curve SECP256R1 parameters */
#define ECC_SECP256R1_32B_WORDS_SIZE 8
/*! @brief number of 32bits word for curve SECP256K1 parameters */
#define ECC_SECP256K1_32B_WORDS_SIZE 8
/*! @brief number of 32bits word for curve BP256R1 parameters */
#define ECC_BP256R1_32B_WORDS_SIZE 8
/*! @brief number of 32bits word for curve SECP384R1 parameters */
#define ECC_SECP384R1_32B_WORDS_SIZE 12
/*! @brief number of 32bits word for curve SECP521R1 parameters */
#define ECC_SECP521R1_32B_WORDS_SIZE 17
/*! @brief number of 32bits word for curve BP384R1 parameters */
#define ECC_BP384R1_32B_WORDS_SIZE 12
/*! @brief number of 32bits word for curve BP512R1 parameters */
#define ECC_BP512R1_32B_WORDS_SIZE 16

/*! @brief number of 64bits word for curve SECP224R1 parameters */
#define ECC_SECP224R1_64B_WORDS_SIZE 4
/*! @brief number of 64bits word for curve SECP256R1 parameters */
#define ECC_SECP256R1_64B_WORDS_SIZE 4
/*! @brief number of 64bits word for curve SECP256K1 parameters */
#define ECC_SECP256K1_64B_WORDS_SIZE 4
/*! @brief number of 64bits word for curve BP256R1 parameters */
#define ECC_BP256R1_64B_WORDS_SIZE 4
/*! @brief number of 64bits word for curve SECP384R1 parameters */
#define ECC_SECP384R1_64B_WORDS_SIZE 6
/*! @brief number of 64bits word for curve SECP521R1 parameters */
#define ECC_SECP521R1_64B_WORDS_SIZE 9
/*! @brief number of 64bits word for curve BP384R1 parameters */
#define ECC_BP384R1_64B_WORDS_SIZE 6
/*! @brief number of 64bits word for curve BP512R1 parameters */
#define ECC_BP512R1_64B_WORDS_SIZE 8

#define ECDSA_BLOCK_SIZE 32
/*! @brief maximum accepted 32 bits word size */
#define ECDSA_MAX_32B_WORDSIZE ECC_SECP521R1_32B_WORDS_SIZE

#define ECDSA_MIN_32B_WORDSIZE ECC_SECP224R1_32B_WORDS_SIZE

// #define SCL_ECC_INVERSE_2_OPTIMIZATION 1
// #define SCL_ECDSA_SIGNATURE_COMPUTATION 0xFF
// #define SCL_ECDSA_SIGNATURE_VERIFICATION 0x00

// we use the SECG terminology (when applicable)
// 8 up to now

/*! @brief standard supported curves (SECG teminology is used) */
enum ecc_std_curves_e
{
    ECC_SECP224R1 = 0,
    ECC_SECP256R1,
    ECC_SECP256K1,
    ECC_SECP384R1,
    ECC_SECP521R1,
    ECC_BP256R1,
    ECC_BP384R1,
    ECC_BP512R1,
    ECC_UNKNOWN_CURVE,
    ECC_CURVE_MAX_NB
};

typedef struct ecc_bignum_jacobian_point_s
{
    uint64_t *x;
    uint64_t *y;
    uint64_t *z;
} ecc_bignum_jacobian_point_t;

typedef struct ecc_affine_point_s
{
    uint8_t *x;
    uint8_t *y;
} ecc_affine_point_t;

typedef struct ecc_affine_const_point_s
{
    const uint8_t *x;
    const uint8_t *y;
} ecc_affine_const_point_t;

typedef struct ecc_signature_s
{
    uint8_t *r;
    uint8_t *s;
} ecc_signature_t;

typedef struct ecc_bignum_affine_point_s
{
    uint64_t *x;
    uint64_t *y;
} ecc_bignum_affine_point_t;

typedef struct ecc_curve_s
{
    const uint64_t *a;
    const uint64_t *b;
    const uint64_t *p;
    const uint64_t *n;
    const ecc_bignum_affine_point_t *g;
    const uint64_t *inverse_2;
    const uint64_t *square_p;
    const uint64_t *precomputed_1_x;
    const uint64_t *precomputed_1_y;
    size_t curve_wsize;
    size_t curve_bsize;
    size_t curve_bitsize;
    enum ecc_std_curves_e curve;
} ecc_curve_t;

/*! @brief SECP256R1 curve */
extern const ecc_curve_t ecc_secp256r1;

/*! @brief  SECP384R1 curve */
extern const ecc_curve_t ecc_secp384r1;

/*! @brief SECP521R1 curve */
extern const ecc_curve_t ecc_secp521r1;

#endif /* SCL_BACKEND_ECC_H */
