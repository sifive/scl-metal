/**
 * @file test_scl_ecc_keygen.c
 * @brief test suite for scl_ecc_keygen.c
 * @details test on key generation for curves SECP256r1, SECP384r1 and SECP521r1
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

#include <stdbool.h>
#include <string.h>

#include <backend/software/scl_soft.h>

#include <scl/scl_ecc_keygen.h>

static int32_t get_data_for_test(const metal_scl_t *const scl,
                                 uint32_t *data_out);

/**
 * We use CRYPTO_CONST_DATA qualifier to allow relocation in RAM to speed up
 * test
 */
CRYPTO_CONST_DATA static const metal_scl_t scl = {
    .trng_func =
        {
            .get_data = get_data_for_test,
        },
    .bignum_func =
        {
            .compare = soft_bignum_compare,
            .compare_len_diff = soft_bignum_compare_len_diff,
            .is_null = soft_bignum_is_null,
            .negate = soft_bignum_negate,
            .inc = soft_bignum_inc,
            .add = soft_bignum_add,
            .sub = soft_bignum_sub,
            .mult = soft_bignum_mult,
            .square = soft_bignum_square_with_mult,
            // .square = soft_bignum_square,
            .leftshift = soft_bignum_leftshift,
            .rightshift = soft_bignum_rightshift,
            .msb_set_in_word = soft_bignum_msb_set_in_word,
            .get_msb_set = soft_bignum_get_msb_set,
            .set_bit = soft_bignum_set_bit,
            .div = soft_bignum_div,
            // .mod = soft_bignum_mod,
            .mod = soft_ecc_mod,
            .set_modulus = soft_bignum_set_modulus,
            .mod_add = soft_bignum_mod_add,
            .mod_sub = soft_bignum_mod_sub,
            // .mod_sub = soft_ecc_mod_sub,
            .mod_mult = soft_bignum_mod_mult,
            .mod_inv = soft_bignum_mod_inv,
            .mod_square = soft_bignum_mod_square,
        },
    .ecc_func =
        {
            .point_on_curve = soft_ecc_point_on_curve,
            .pubkey_generation = soft_ecc_pubkey_generation,
            .keypair_generation = soft_ecc_keypair_generation,
        },
};

int32_t get_data_for_test(const metal_scl_t *const scl_ctx, uint32_t *data_out)
{
    (void)scl_ctx;
    *data_out = 0xA5A5A5A5;
    return (SCL_OK);
}

TEST_GROUP(scl_ecc_keygen);

TEST_SETUP(scl_ecc_keygen) {}

TEST_TEAR_DOWN(scl_ecc_keygen) {}

TEST(scl_ecc_keygen, scl_ecc_keygen_secp256r1_all_in_one)
{
    int32_t result;

    uint8_t priv_key[ECC_SECP256R1_BYTESIZE] = {0};
    uint8_t point_x[ECC_SECP256R1_BYTESIZE] = {0};
    uint8_t point_y[ECC_SECP256R1_BYTESIZE] = {0};

    static const uint8_t expected_priv_key[ECC_SECP256R1_BYTESIZE] = {
        0xa5, 0xA5, 0xA5, 0xA5, 0xa5, 0xA5, 0xA5, 0xA5, 0xa5, 0xA5, 0xA5,
        0xA5, 0xa5, 0xA5, 0xA5, 0xA5, 0xa5, 0xA5, 0xA5, 0xA5, 0xa5, 0xA5,
        0xA5, 0xA5, 0xa5, 0xA5, 0xA5, 0xA5, 0xa5, 0xA5, 0xA5, 0xA5};
    static const uint8_t expected_point_x[ECC_SECP256R1_BYTESIZE] = {
        0x7E, 0x44, 0xE9, 0x6E, 0x91, 0x23, 0x4B, 0xD1, 0xAE, 0xA4, 0x03,
        0x46, 0xAE, 0x03, 0x15, 0x88, 0xEA, 0x33, 0xE6, 0x4E, 0x73, 0x4F,
        0xE6, 0x41, 0x65, 0x1F, 0x46, 0xD4, 0x43, 0xFD, 0xEE, 0x3C};
    static const uint8_t expected_point_y[ECC_SECP256R1_BYTESIZE] = {
        0x5A, 0x09, 0x6D, 0x09, 0x71, 0xE7, 0x61, 0x34, 0x0D, 0xBB, 0x91,
        0x87, 0xAF, 0xF5, 0x74, 0x6E, 0xD0, 0xB2, 0x87, 0x03, 0xAB, 0xC4,
        0x9A, 0x1A, 0xCA, 0xF2, 0x1B, 0x6A, 0x92, 0x91, 0x65, 0xD7};

    ecc_affine_point_t pub_key = {.x = point_x, .y = point_y};

    result =
        scl_ecc_keypair_generation(&scl, &ecc_secp256r1, priv_key, &pub_key);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_x, point_x,
                                 ECC_SECP256R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_y, point_y,
                                 ECC_SECP256R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_priv_key, priv_key,
                                 ECC_SECP256R1_BYTESIZE);

    memset(point_x, 0, sizeof(point_x));
    memset(point_y, 0, sizeof(point_y));

    result =
        scl_ecc_pubkey_generation(&scl, &ecc_secp256r1, priv_key, &pub_key);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_x, point_x,
                                 ECC_SECP256R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_y, point_y,
                                 ECC_SECP256R1_BYTESIZE);

    result = scl_ecc_key_on_curve(&scl, &ecc_secp256r1,
                                  (ecc_affine_const_point_t *)&pub_key);
    TEST_ASSERT_TRUE(SCL_OK == result);

    point_x[0] = 0x01;

    result = scl_ecc_key_on_curve(&scl, &ecc_secp256r1,
                                  (ecc_affine_const_point_t *)&pub_key);
    TEST_ASSERT_TRUE(SCL_ERR_POINT == result);
}

TEST(scl_ecc_keygen, scl_ecc_keygen_secp384r1_all_in_one)
{
    int32_t result;

    uint8_t priv_key[ECC_SECP384R1_BYTESIZE] = {0};
    uint8_t point_x[ECC_SECP384R1_BYTESIZE] = {0};
    uint8_t point_y[ECC_SECP384R1_BYTESIZE] = {0};

    static const uint8_t expected_priv_key[ECC_SECP384R1_BYTESIZE] = {
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xA5, 0xA5, 0xA5,
        0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
    static const uint8_t expected_point_x[ECC_SECP384R1_BYTESIZE] = {
        0xA0, 0x40, 0xF4, 0x78, 0x57, 0x49, 0x72, 0xA3, 0x8D, 0x2A, 0x97, 0x84,
        0xE3, 0x52, 0x3C, 0x1D, 0xE2, 0xE5, 0x64, 0xED, 0x37, 0xC3, 0x44, 0xF9,
        0x57, 0x1D, 0xBE, 0x72, 0x67, 0xF3, 0x53, 0xA6, 0x86, 0xAF, 0x60, 0xF2,
        0x74, 0x5C, 0xA9, 0x57, 0x29, 0xFB, 0x90, 0x18, 0x56, 0x2F, 0x82, 0x19};
    static const uint8_t expected_point_y[ECC_SECP384R1_BYTESIZE] = {
        0x3D, 0x72, 0x4D, 0x19, 0x11, 0x17, 0xD9, 0xF1, 0x4B, 0x16, 0xBA, 0xDD,
        0x48, 0x4E, 0x28, 0x5B, 0x98, 0x0A, 0xB7, 0xD8, 0x96, 0x11, 0x01, 0x1E,
        0x89, 0x57, 0x98, 0x59, 0xD4, 0x41, 0xD4, 0x84, 0xE3, 0x17, 0xAA, 0xCA,
        0xCB, 0xE2, 0xC1, 0x66, 0x8E, 0x21, 0x2A, 0x7E, 0x5F, 0x38, 0x0D, 0xB7};

    ecc_affine_point_t pub_key = {.x = point_x, .y = point_y};

    result =
        scl_ecc_keypair_generation(&scl, &ecc_secp384r1, priv_key, &pub_key);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_x, point_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_y, point_y,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_priv_key, priv_key,
                                 ECC_SECP384R1_BYTESIZE);

    memset(point_x, 0, sizeof(point_x));
    memset(point_y, 0, sizeof(point_y));

    result =
        scl_ecc_pubkey_generation(&scl, &ecc_secp384r1, priv_key, &pub_key);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_x, point_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_y, point_y,
                                 ECC_SECP384R1_BYTESIZE);

    result = scl_ecc_key_on_curve(&scl, &ecc_secp384r1,
                                  (ecc_affine_const_point_t *)&pub_key);
    TEST_ASSERT_TRUE(SCL_OK == result);

    point_x[0] = 0x01;

    result = scl_ecc_key_on_curve(&scl, &ecc_secp384r1,
                                  (ecc_affine_const_point_t *)&pub_key);
    TEST_ASSERT_TRUE(SCL_ERR_POINT == result);
}

TEST(scl_ecc_keygen, scl_ecc_keygen_secp521r1_all_in_one)
{
    int32_t result;

    uint8_t priv_key[ECC_SECP521R1_BYTESIZE] = {0};
    uint8_t point_x[ECC_SECP521R1_BYTESIZE] = {0};
    uint8_t point_y[ECC_SECP521R1_BYTESIZE] = {0};

    static const uint8_t expected_priv_key[ECC_SECP521R1_BYTESIZE] = {
        0x01, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5};
    static const uint8_t expected_point_x[ECC_SECP521R1_BYTESIZE] = {
        0x00, 0x6d, 0x5c, 0xc9, 0x62, 0x39, 0xf4, 0x1a, 0xc9, 0x0e, 0x92,
        0x1e, 0xaa, 0xfa, 0x74, 0x82, 0xab, 0x18, 0xc2, 0x25, 0x09, 0x9f,
        0xfe, 0x73, 0x0f, 0xec, 0x44, 0xbc, 0xd0, 0x42, 0x43, 0x17, 0xc3,
        0xbb, 0xe7, 0xa9, 0x95, 0x9c, 0xc7, 0xc3, 0xdf, 0x5f, 0x4f, 0x89,
        0xee, 0xf6, 0x73, 0xec, 0x9d, 0xda, 0xed, 0x9d, 0x89, 0xc9, 0x1f,
        0x29, 0x9c, 0x86, 0xad, 0xbd, 0xc3, 0x86, 0xc7, 0x92, 0x5a, 0xe1};
    static const uint8_t expected_point_y[ECC_SECP521R1_BYTESIZE] = {
        0x01, 0x8b, 0x0c, 0x3c, 0xcd, 0x5f, 0x7d, 0x85, 0xb1, 0x48, 0x9b,
        0xa0, 0x93, 0x39, 0x5f, 0x7d, 0xbd, 0x02, 0x22, 0x40, 0x9b, 0x24,
        0x36, 0xbc, 0xe0, 0x9d, 0x02, 0x28, 0x75, 0x8e, 0xf3, 0xbd, 0x42,
        0xf7, 0x87, 0x7b, 0xf4, 0xa0, 0xff, 0x7c, 0xeb, 0xb2, 0x9a, 0x1b,
        0x0c, 0x4f, 0xa6, 0xbd, 0xda, 0x81, 0x75, 0xfd, 0x61, 0xf4, 0x95,
        0x97, 0xe5, 0xca, 0x22, 0x2c, 0x0a, 0xf3, 0xa8, 0x27, 0x13, 0xd7};

    ecc_affine_point_t pub_key = {.x = point_x, .y = point_y};

    result =
        scl_ecc_keypair_generation(&scl, &ecc_secp521r1, priv_key, &pub_key);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_x, point_x,
                                 ECC_SECP521R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_y, point_y,
                                 ECC_SECP521R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_priv_key, priv_key,
                                 ECC_SECP521R1_BYTESIZE);

    memset(point_x, 0, sizeof(point_x));
    memset(point_y, 0, sizeof(point_y));

    result =
        scl_ecc_pubkey_generation(&scl, &ecc_secp521r1, priv_key, &pub_key);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_x, point_x,
                                 ECC_SECP521R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_point_y, point_y,
                                 ECC_SECP521R1_BYTESIZE);

    result = scl_ecc_key_on_curve(&scl, &ecc_secp521r1,
                                  (ecc_affine_const_point_t *)&pub_key);
    TEST_ASSERT_TRUE(SCL_OK == result);

    point_x[0] = 0x01;

    result = scl_ecc_key_on_curve(&scl, &ecc_secp521r1,
                                  (ecc_affine_const_point_t *)&pub_key);
    TEST_ASSERT_TRUE(SCL_ERR_POINT == result);
}
