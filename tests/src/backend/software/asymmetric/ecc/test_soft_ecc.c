/**
 * @file test_soft_ecc.c
 * @brief test suite for soft_ecc.c
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

/**
 * We use CRYPTO_CONST_DATA qualifier to allow relocation in RAM to speed up
 * test
 */
CRYPTO_CONST_DATA static const metal_scl_t scl = {
    .hca_base = 0,
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
            .mod = soft_bignum_mod,
            .set_modulus = soft_bignum_set_modulus,
            .mod_add = soft_bignum_mod_add,
            .mod_sub = soft_bignum_mod_sub,
            .mod_mult = soft_bignum_mod_mult,
            .mod_inv = soft_bignum_mod_inv,
            .mod_square = soft_bignum_mod_square,
        },
};

TEST_GROUP(soft_ecc);

TEST_SETUP(soft_ecc) {}

TEST_TEAR_DOWN(soft_ecc) {}

TEST(soft_ecc, test_p384r1_affine_2_jacobian_2_affine)
{
    int32_t result = 0;

    uint64_t point_x[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0xE8239FC890BC6894, 0xC61EF3EF31AE0D87, 0xC5AD236CA59684BE,
        0xBABCE4EB75047E7A, 0xA75A8848900CC063, 0xA011B3C98CCC2720};

    uint64_t point_y[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0x96455AEE5D3E8912, 0xA0DA7CBF700931A6, 0xF8BDABFB61F95731,
        0x9A2708BE527AE3C9, 0x024C8F69D35F423E, 0xE03D61232DEDE896};

    static const uint64_t point_expected_x[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0xE8239FC890BC6894, 0xC61EF3EF31AE0D87, 0xC5AD236CA59684BE,
        0xBABCE4EB75047E7A, 0xA75A8848900CC063, 0xA011B3C98CCC2720};

    static const uint64_t point_expected_y[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0x96455AEE5D3E8912, 0xA0DA7CBF700931A6, 0xF8BDABFB61F95731,
        0x9A2708BE527AE3C9, 0x024C8F69D35F423E, 0xE03D61232DEDE896};

    uint64_t point_jac_x[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_jac_y[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_jac_z[ECC_SECP384R1_64B_WORDS_SIZE] = {0};

    ecc_bignum_affine_point_t point = {.x = point_x, .y = point_y};
    ecc_bignum_jacobian_point_t point_jac = {
        .x = point_jac_x, .y = point_jac_y, .z = point_jac_z};

    result = soft_ecc_convert_affine_to_jacobian(
        &scl, &ecc_secp384r1, (ecc_bignum_affine_const_point_t *)&point,
        &point_jac, ECC_SECP384R1_32B_WORDS_SIZE);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_ecc_convert_jacobian_to_affine(
        &scl, &ecc_secp384r1, &point_jac, &point, ECC_SECP384R1_32B_WORDS_SIZE);

    TEST_ASSERT_TRUE(SCL_OK == result);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_x, point_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_y, point_y,
                                 ECC_SECP384R1_BYTESIZE);
}

/* Addition */
TEST(soft_ecc, test_p384r1_double_affine_point_via_jacobian)
{
    int32_t result = 0;

    uint64_t point_x[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0xE8239FC890BC6894, 0xC61EF3EF31AE0D87, 0xC5AD236CA59684BE,
        0xBABCE4EB75047E7A, 0xA75A8848900CC063, 0xA011B3C98CCC2720};

    uint64_t point_y[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0x96455AEE5D3E8912, 0xA0DA7CBF700931A6, 0xF8BDABFB61F95731,
        0x9A2708BE527AE3C9, 0x024C8F69D35F423E, 0xE03D61232DEDE896};

    static const uint64_t point_expected_x[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0x19E63250FA210E7A, 0x5DD95D157FFA6D40, 0xBC442EEC637045B9,
        0x38D9EB89EBA8D821, 0x9F0B89A7F2352465, 0x2A70394A45A7F16A};

    static const uint64_t point_expected_y[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0x204D242FF2A87083, 0x743B7B7C2E90AF89, 0x4223F8C849D15897,
        0xA6F54667A5903978, 0x12E307875CD94CC1, 0x85E0719553E1310C};

    uint64_t point_jac_x[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_jac_y[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_jac_z[ECC_SECP384R1_64B_WORDS_SIZE] = {0};

    ecc_bignum_affine_point_t point = {.x = point_x, .y = point_y};
    ecc_bignum_jacobian_point_t point_jac = {
        .x = point_jac_x, .y = point_jac_y, .z = point_jac_z};

    result = soft_ecc_convert_affine_to_jacobian(
        &scl, &ecc_secp384r1, (ecc_bignum_affine_const_point_t *)&point,
        &point_jac, ECC_SECP384R1_32B_WORDS_SIZE);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_ecc_double_jacobian(&scl, &ecc_secp384r1, &point_jac,
                                      &point_jac, ECC_SECP384R1_32B_WORDS_SIZE);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_ecc_convert_jacobian_to_affine(
        &scl, &ecc_secp384r1, &point_jac, &point, ECC_SECP384R1_32B_WORDS_SIZE);

    TEST_ASSERT_TRUE(SCL_OK == result);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_x, point_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_y, point_y,
                                 ECC_SECP384R1_BYTESIZE);
}

TEST(soft_ecc, test_p384r1_add_affine_point_via_jacobian)
{
    int32_t result = 0;

    uint64_t point_1_x[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0xE8239FC890BC6894, 0xC61EF3EF31AE0D87, 0xC5AD236CA59684BE,
        0xBABCE4EB75047E7A, 0xA75A8848900CC063, 0xA011B3C98CCC2720};

    uint64_t point_1_y[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0x96455AEE5D3E8912, 0xA0DA7CBF700931A6, 0xF8BDABFB61F95731,
        0x9A2708BE527AE3C9, 0x024C8F69D35F423E, 0xE03D61232DEDE896};

    uint64_t point_2_x[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0xBFAA1EB3B390DBFA, 0x62E5751DE484DDD2, 0xF16D54C2C6738D6E,
        0x7CE17409915FBB40, 0x7E4CEEB38FA9E747, 0x0F898007251672BC};

    uint64_t point_2_y[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0x0F5D52BED5693395, 0xE459A59E70947C50, 0x2DEE2BCBC649B425,
        0xCC61342E5F3060CD, 0x6BFDA3B7E1206C55, 0xA4A4F7F882FE209D};

    static const uint64_t point_expected_x[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0xF9AFDB62A269112C, 0x4F674222FC299B31, 0xF1D4A9A5A4092BC6,
        0x4B65085D26F1E2B9, 0xF3624D0FF7BDFF2C, 0xD8AC864C156ED992};

    static const uint64_t point_expected_y[ECC_SECP384R1_64B_WORDS_SIZE] = {
        0xBA14BD0E731F5BA3, 0xC67A07E21FFA99F7, 0x866DD917F44879D1,
        0x19D9705110670710, 0x1A87FDE0EAD01FBD, 0xD7DFBF6E1E5EAA0A};

    uint64_t point_1_jac_x[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_1_jac_y[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_1_jac_z[ECC_SECP384R1_64B_WORDS_SIZE] = {0};

    uint64_t point_2_jac_x[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_2_jac_y[ECC_SECP384R1_64B_WORDS_SIZE] = {0};
    uint64_t point_2_jac_z[ECC_SECP384R1_64B_WORDS_SIZE] = {0};

    ecc_bignum_affine_point_t point_1 = {.x = point_1_x, .y = point_1_y};
    ecc_bignum_affine_point_t point_2 = {.x = point_2_x, .y = point_2_y};

    ecc_bignum_jacobian_point_t point_1_jac = {
        .x = point_1_jac_x, .y = point_1_jac_y, .z = point_1_jac_z};
    ecc_bignum_jacobian_point_t point_2_jac = {
        .x = point_2_jac_x, .y = point_2_jac_y, .z = point_2_jac_z};

    result = soft_ecc_convert_affine_to_jacobian(
        &scl, &ecc_secp384r1, (ecc_bignum_affine_const_point_t *)&point_1,
        &point_1_jac, ECC_SECP384R1_32B_WORDS_SIZE);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_ecc_convert_affine_to_jacobian(
        &scl, &ecc_secp384r1, (ecc_bignum_affine_const_point_t *)&point_2,
        &point_2_jac, ECC_SECP384R1_32B_WORDS_SIZE);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_ecc_add_jacobian_jacobian(&scl, &ecc_secp384r1, &point_1_jac,
                                            &point_2_jac, &point_1_jac,
                                            ECC_SECP384R1_32B_WORDS_SIZE);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_ecc_convert_jacobian_to_affine(&scl, &ecc_secp384r1,
                                                 &point_1_jac, &point_1,
                                                 ECC_SECP384R1_32B_WORDS_SIZE);

    TEST_ASSERT_TRUE(SCL_OK == result);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_x, point_1_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_y, point_1_y,
                                 ECC_SECP384R1_BYTESIZE);
}

/* test co-Z multiplication */

TEST(soft_ecc, test_soft_ecc_mult_coz)
{
    int32_t result = 0;

    uint32_t point_x[ECC_SECP384R1_32B_WORDS_SIZE]
        __attribute__((aligned(8))) = {0};

    uint32_t point_y[ECC_SECP384R1_32B_WORDS_SIZE]
        __attribute__((aligned(8))) = {0};

    uint32_t k[ECC_SECP384R1_32B_WORDS_SIZE + 1] __attribute__((aligned(8))) = {
        0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
        0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
        0xa5a5a5a5, 0xa5a5a5a5, 0x00000001};

    static const uint32_t point_expected_x[ECC_SECP384R1_32B_WORDS_SIZE] = {
        0xce9e055c, 0x0b28d27c, 0xcec1e64e, 0x09aa0f24, 0x32cce9e8, 0x68067caf,
        0x144a6b52, 0x6e0f8c76, 0xcc00946c, 0xa134500e, 0xcea11fef, 0x521cd0aa};

    static const uint32_t point_expected_y[ECC_SECP384R1_32B_WORDS_SIZE] = {
        0x27bf720d, 0xe546d499, 0xb9f02ddd, 0x1a866443, 0xb6eeea36, 0xccf845f9,
        0x1dd61ff3, 0xdb890fcd, 0xea7f8e66, 0xb480895b, 0x028b8f1d, 0x911e5cc9};

    ecc_bignum_affine_point_t output_aff_pnt = {.x = (uint64_t *)point_x,
                                                .y = (uint64_t *)point_y};

    result =
        soft_ecc_mult_coz(&scl, &ecc_secp384r1, ecc_secp384r1.g, (uint64_t *)k,
                          ECC_SECP384R1_32B_WORDS_SIZE + 1, &output_aff_pnt);

    TEST_ASSERT_TRUE(SCL_OK == result);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_x, point_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_expected_y, point_y,
                                 ECC_SECP384R1_BYTESIZE);
}

/* test co-Z add c */

TEST(soft_ecc, test_soft_ecc_xycz_addc)
{
    int32_t result = 0;

    uint32_t point_1_x[ECC_SECP384R1_32B_WORDS_SIZE]
        __attribute__((aligned(8))) = {0x40ecd64d, 0x9814b74b, 0xe81f17d6,
                                       0x3681efa0, 0xf27113fe, 0xdb0ddeeb,
                                       0xf3d2faaf, 0x781a2808, 0xa2c12671,
                                       0x78191950, 0x334272e3, 0x80bcdae0};

    uint32_t point_1_y[ECC_SECP384R1_32B_WORDS_SIZE]
        __attribute__((aligned(8))) = {0xf2e97b2f, 0xe3d9b7ad, 0x05a2a998,
                                       0xd2f7bcf9, 0x0ef5b1ee, 0x8584ebe9,
                                       0x720e9aff, 0x6cf5ed43, 0xf846ed09,
                                       0x3262d310, 0x7215c02c, 0xbd7bfa6d};

    uint32_t point_2_x[ECC_SECP384R1_32B_WORDS_SIZE]
        __attribute__((aligned(8))) = {0xc5e40b94, 0x59ab4f6e, 0xb7ba23cd,
                                       0xb223d61a, 0xa906c671, 0x6c54c93e,
                                       0xe6b5d561, 0xd279318f, 0xe34e6d18,
                                       0x52eebd29, 0x81ef5f4f, 0xe50dbe09};

    uint32_t point_2_y[ECC_SECP384R1_32B_WORDS_SIZE]
        __attribute__((aligned(8))) = {0xf1e0757a, 0x9dd63d29, 0x0ad2205e,
                                       0x73333e36, 0x1fe41e83, 0x08c2e53b,
                                       0xb9e0a162, 0xc068b421, 0x809fb3a5,
                                       0xd90b8c1a, 0x52ac7ebe, 0x5b939b5a};

    static const uint32_t point_1_expected_x[ECC_SECP384R1_32B_WORDS_SIZE] = {
        0xfa15e069, 0xa3b9403a, 0x04b928ee, 0x142ebb65, 0x759695fd, 0xacbab3b2,
        0x29a25512, 0xb0125625, 0x0710b759, 0x4df8dfd0, 0xa59f4652, 0x1bcf9599};

    static const uint32_t point_1_expected_y[ECC_SECP384R1_32B_WORDS_SIZE] = {
        0x106d7177, 0xabf85d07, 0x0ca67a20, 0xb013be41, 0x0e542a4b, 0xb988d006,
        0x95179c39, 0x6c7670a4, 0xaf8438db, 0x351e617a, 0x530c18e1, 0x52b7472c};

    static const uint32_t point_2_expected_x[ECC_SECP384R1_32B_WORDS_SIZE] = {
        0xe772e1d2, 0x655dba40, 0x808fcfb9, 0xeb9c3dfd, 0x40af1b0c, 0x46e0f61e,
        0x7d94b9a2, 0xfbe129ec, 0x17895867, 0xa238d093, 0x053ebb61, 0xb24a7bc8};

    static const uint32_t point_2_expected_y[ECC_SECP384R1_32B_WORDS_SIZE] = {
        0xea05b779, 0xf12059cb, 0xd08eb803, 0xa1e09845, 0x49ad0318, 0x689a5c95,
        0x652e6476, 0xb13a9dec, 0x80417d2e, 0xcc886b48, 0xa3cd3b32, 0xd7be9639};

    ecc_bignum_affine_point_t p[2];

    p[0].x = (uint64_t *)point_1_x;
    p[0].y = (uint64_t *)point_1_y;
    p[1].x = (uint64_t *)point_2_x;
    p[1].y = (uint64_t *)point_2_y;

    result = soft_ecc_xycz_addc(
        &scl, &ecc_secp384r1, (ecc_bignum_affine_const_point_t *)&p[1],
        (ecc_bignum_affine_const_point_t *)&p[0], &p[0], &p[1]);

    TEST_ASSERT_TRUE(SCL_OK == result);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_1_expected_x, point_1_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_1_expected_y, point_1_y,
                                 ECC_SECP384R1_BYTESIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_2_expected_x, point_2_x,
                                 ECC_SECP384R1_BYTESIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(point_2_expected_y, point_2_y,
                                 ECC_SECP384R1_BYTESIZE);
}
