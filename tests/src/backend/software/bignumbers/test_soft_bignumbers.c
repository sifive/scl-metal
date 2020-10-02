#include "unity.h"
/**
 * @file test_soft_bignumbers.c
 * @brief test suite for hca_sha.c on sha 224 algorithm
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity_fixture.h"

#include <stdbool.h>
#include <string.h>

#include <backend/software/scl_soft.h>
#include <backend/api/macro.h>

static const metal_scl_t scl = {
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
            .square = soft_bignum_square,
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

TEST_GROUP(soft_bignumbers);

TEST_SETUP(soft_bignumbers) {}

TEST_TEAR_DOWN(soft_bignumbers) {}

/* Addition */
TEST(soft_bignumbers, soft_bignum_add_size_0)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0;

    result = soft_bignum_add(NULL, &in_a, &in_b, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_add_size_1)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0x00000000FFFFFFFFUL;

    result = soft_bignum_add(NULL, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_add_size_1_with_carry)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFFUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0;

    result = soft_bignum_add(NULL, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_add_size_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFFUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0x0000000100000000UL;

    result = soft_bignum_add(NULL, &in_a, &in_b, &out, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_add_size_2_with_carry)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0;

    result = soft_bignum_add(NULL, &in_a, &in_b, &out, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_add_size_5)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000EFFFFFFFUL};
    static const uint64_t in_b[3] = {1, 0, 0};
    uint64_t out[4] = {0, 0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[4] = {0, 0, 0x00000000F0000000UL,
                                             0xFFFFFFFFFFFFFFFFUL};

    result = soft_bignum_add(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_add_size_5_with_carry)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000FFFFFFFFUL};
    static const uint64_t in_b[3] = {1, 0, 0};
    uint64_t out[3] = {0};
    static const uint64_t expected_out[3] = {0, 0, 0};

    result = soft_bignum_add(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_add_summ_all_FF)
{
    int32_t result = 0;

    static const uint64_t in_a[10] = {
        0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t in_b[10] = {1, 0, 0, 0, 0xFFFFFFFF00000000UL,
                                      0, 0, 0, 0, 0};
    uint64_t out[10] = {0};
    static const uint64_t expected_out[10] = {
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL};

    result =
        soft_bignum_add(NULL, in_a, in_b, out, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_add_carry_1)
{
    int32_t result = 0;

    static const uint64_t in_a[10] = {
        0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0};
    static const uint64_t in_b[10] = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t out[10] = {0};
    static const uint64_t expected_out[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    result = soft_bignum_add(NULL, in_a, in_b, out, NB_32BITS_WORDS(in_a) - 2);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_add_carry_2)
{
    int32_t result = 0;

    static const uint64_t in_a[10] = {
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t in_b[10] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t out[10] = {0};
    static const uint64_t expected_out[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    result =
        soft_bignum_add(NULL, in_a, in_b, out, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_add_in_a_is_output)
{
    int32_t result = 0;

    uint64_t in_a[10] = {0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL};
    static const uint64_t in_b[10] = {
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL};

    static const uint64_t expected_out[10] = {
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x1111111122222222UL};

    result = soft_bignum_add(NULL, in_a, in_b, in_a, NB_32BITS_WORDS(in_a) - 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in_a, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_add_in_b_is_output)
{
    int32_t result = 0;

    static const uint64_t in_a[10] = {
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL};
    uint64_t in_b[10] = {0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL};

    static const uint64_t expected_out[10] = {
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x1111111122222222UL};

    result = soft_bignum_add(NULL, in_a, in_b, in_b, NB_32BITS_WORDS(in_a) - 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in_b, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_add_100_bytes)
{
    int32_t result = 0;

    uint8_t in_a[100] __attribute__((aligned(8))) = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0,
        0xff, 0xff, 0xff, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0,
        0xff, 0xff, 0xff, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f,
        0x00, 0x00, 0x00, 0x00};

    static const uint8_t in_b[100] __attribute__((aligned(8))) = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
        0xff, 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
        0xff, 0xff, 0xff, 0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
        0x00, 0x00, 0x00, 0x00};

    static const uint8_t expected_out[100] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD0,
        0xFF, 0xFF, 0xFF, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD0,
        0xFF, 0xFF, 0xFF, 0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2F};

    result =
        soft_bignum_add(NULL, (const uint64_t *)in_a, (const uint64_t *)in_b,
                        (uint64_t *)in_a, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in_a, sizeof(expected_out));
}

/* Substraction */
TEST(soft_bignumbers, soft_bignum_sub_size_0)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0;

    result = soft_bignum_sub(NULL, &in_a, &in_b, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_sub_size_1)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0x00000000FFFFFFFDUL;

    result = soft_bignum_sub(NULL, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_sub_size_1_with_carry)
{
    int32_t result = 0;

    static const uint64_t in_a = 1;
    static const uint64_t in_b = 0x00000000FFFFFFFFUL;
    uint64_t out = 0;
    static const uint64_t expected_out = 2;

    result = soft_bignum_sub(NULL, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_sub_size_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t expected_out = 0xFFFFFFFFFFFFFFFDUL;

    result = soft_bignum_sub(NULL, &in_a, &in_b, &out, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_sub_size_2_with_carry)
{
    int32_t result = 0;

    static const uint64_t in_a = 1;
    static const uint64_t in_b = 0x00000000FFFFFFFFUL;
    uint64_t out = 0;
    static const uint64_t expected_out = 0xFFFFFFFF00000002;

    result = soft_bignum_sub(NULL, &in_a, &in_b, &out, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_sub_size_5)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000EFFFFFFFUL};
    static const uint64_t in_b[3] = {1, 0, 0};
    uint64_t out[4] = {0, 0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[4] = {
        0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL, 0x00000000EFFFFFFFUL,
        0xFFFFFFFFFFFFFFFFUL};

    result = soft_bignum_sub(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_sub_size_5_with_carry)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {1, 0, 0};
    static const uint64_t in_b[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000FFFFFFFFUL};

    uint64_t out[3] = {0};
    static const uint64_t expected_out[3] = {
        0x0000000000000002, 0x0000000000000000UL, 0x0000000000000000UL};

    result = soft_bignum_sub(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_sub_size_5_with_carry_2)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0, 2, 0};
    static const uint64_t in_b[3] = {1, 0xFF, 0};

    uint64_t out[3] = {0};
    static const uint64_t expected_out[3] = {
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFF02UL, 0x00000000FFFFFFFFUL};

    result = soft_bignum_sub(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_sub_in_a_is_output)
{
    int32_t result = 0;

    uint64_t in_a[10] = {0x3333333333333333UL, 0x3333333333333333UL,
                         0x3333333333333333UL, 0x3333333333333333UL,
                         0x3333333333333333UL, 0x3333333333333333UL,
                         0x3333333333333333UL, 0x3333333333333333UL,
                         0x3333333333333333UL, 0x1111111133333333UL};
    static const uint64_t in_b[10] = {
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL, 0x1111111111111111UL, 0x1111111111111111UL,
        0x1111111111111111UL};

    static const uint64_t expected_out[10] = {
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x1111111122222222UL};

    result = soft_bignum_sub(NULL, in_a, in_b, in_a, NB_32BITS_WORDS(in_a) - 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in_a, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_sub_in_b_is_output)
{
    int32_t result = 0;

    static const uint64_t in_a[10] = {
        0x3333333333333333UL, 0x3333333333333333UL, 0x3333333333333333UL,
        0x3333333333333333UL, 0x3333333333333333UL, 0x3333333333333333UL,
        0x3333333333333333UL, 0x3333333333333333UL, 0x3333333333333333UL,
        0x1111111133333333UL};
    uint64_t in_b[10] = {0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL,
                         0x1111111111111111UL, 0x1111111111111111UL};

    static const uint64_t expected_out[10] = {
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x2222222222222222UL, 0x2222222222222222UL, 0x2222222222222222UL,
        0x1111111122222222UL};

    result = soft_bignum_sub(NULL, in_a, in_b, in_b, NB_32BITS_WORDS(in_a) - 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in_b, sizeof(expected_out));
}

/* Increment by one */
TEST(soft_bignumbers, soft_bignum_inc_size_0)
{
    int32_t result = 0;

    uint64_t in = 0;
    static const uint64_t expected_out = 0;

    result = soft_bignum_inc(NULL, &in, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_inc_size_1)
{
    int32_t result = 0;

    uint64_t in = 0x00000000FFFFFFFEUL;
    static const uint64_t expected_out = 0x00000000FFFFFFFFUL;

    result = soft_bignum_inc(NULL, &in, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_inc_size_1_with_carry)
{
    int32_t result = 0;

    uint64_t in = 0x00000000FFFFFFFFUL;
    static const uint64_t expected_out = 0;

    result = soft_bignum_inc(NULL, &in, 1);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_inc_size_2)
{
    int32_t result = 0;

    uint64_t in = 0x00000000FFFFFFFFUL;
    static const uint64_t expected_out = 0x0000000100000000UL;

    result = soft_bignum_inc(NULL, &in, NB_32BITS_WORDS(in));

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_inc_size_2_with_carry)
{
    int32_t result = 0;
    uint64_t in = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t expected_out = 0;

    result = soft_bignum_inc(NULL, &in, NB_32BITS_WORDS(in));

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_inc_size_5)
{
    int32_t result = 0;
    uint64_t in[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                      0x00000000EFFFFFFFUL};
    static const uint64_t expected_out[3] = {0, 0, 0x00000000F0000000UL};

    result = soft_bignum_inc(NULL, in, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_inc_size_5_with_carry)
{
    int32_t result = 0;
    uint64_t in[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                      0x00000000FFFFFFFFUL};
    static const uint64_t expected_out[3] = {0, 0, 0};

    result = soft_bignum_inc(NULL, in, 5);

    TEST_ASSERT_TRUE(1 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

/* Compare */
TEST(soft_bignumbers, soft_bignum_compare_a_equals_b)
{
    int32_t result = 0;
    size_t word_size;

    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    word_size = NB_32BITS_WORDS(b);

    result = soft_bignum_compare(NULL, a, b, word_size);

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_a_greater_than_b_lsb)
{
    int32_t result = 0;
    size_t word_size;

    static const uint64_t a[24] = {
        0xF2A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    word_size = NB_32BITS_WORDS(b);

    result = soft_bignum_compare(NULL, a, b, word_size);

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_a_greater_than_b_msb)
{
    int32_t result = 0;
    size_t word_size;

    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3F798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    word_size = NB_32BITS_WORDS(b);

    result = soft_bignum_compare(NULL, a, b, word_size);

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_a_lower_than_b_lsb)
{
    int32_t result = 0;
    size_t word_size;

    static const uint64_t a[24] = {
        0xF0A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    word_size = NB_32BITS_WORDS(b);

    result = soft_bignum_compare(NULL, a, b, word_size);

    TEST_ASSERT_TRUE(-1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_a_lower_than_b_msb)
{
    int32_t result = 0;
    size_t word_size;

    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3D798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    word_size = NB_32BITS_WORDS(b);

    result = soft_bignum_compare(NULL, a, b, word_size);

    TEST_ASSERT_TRUE(-1 == result);
}

/* Multiplication */
TEST(soft_bignumbers, soft_bignum_mult_size_0)
{
    int32_t result = 0;
    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out[2] = {0};
    static const uint64_t expected_out[2] = {0};

    result = soft_bignum_mult(NULL, &in_a, &in_b, out, 0);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
}

TEST(soft_bignumbers, soft_bignum_mult_size_1)
{
    int32_t result = 0;
    static const uint64_t in_a = 0x00000000FFFFFFFFUL;
    static const uint64_t in_b = 0x00000000FFFFFFFFUL;
    uint64_t out = 0;
    static const uint64_t expected_out = 0xFFFFFFFE00000001UL;

    result = soft_bignum_mult(NULL, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(expected_out == out);
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_mult_size_2)
{
    int32_t result = 0;
    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t in_b = 0xFFFFFFFFFFFFFFFFUL;
    uint64_t out[2] = {0};
    static const uint64_t expected_out[2] = {0x0000000000000001UL,
                                             0xFFFFFFFFFFFFFFFEUL};

    result = soft_bignum_mult(NULL, &in_a, &in_b, out, NB_32BITS_WORDS(in_a));

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_mult_size_5)
{
    int32_t result = 0;
    static const uint64_t in_a[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000FFFFFFFFUL};
    static const uint64_t in_b[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000FFFFFFFFUL};

    uint64_t out[5] = {0};
    static const uint64_t expected_out[5] = {
        0x0000000000000001UL, 0x0000000000000000UL, 0xFFFFFFFE00000000UL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL};

    result = soft_bignum_mult(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_mult_size_5_zero)
{
    int32_t result = 0;
    static const uint64_t in_a[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000FFFFFFFFUL};
    static const uint64_t in_b[3] = {0, 0, 0};

    uint64_t out[5] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                       0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                       0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[5] = {0, 0, 0, 0, 0};

    result = soft_bignum_mult(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_mult_size_5_identity)
{
    int32_t result = 0;
    static const uint64_t in_a[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                     0x00000000FFFFFFFFUL};
    static const uint64_t in_b[3] = {1, 0, 0};

    uint64_t out[5] = {0, 0, 0, 0, 0};
    static const uint64_t expected_out[5] = {
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFFUL, 0, 0};

    result = soft_bignum_mult(NULL, in_a, in_b, out, 5);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_mult_size_12)
{
    int32_t result = 0;

    static const uint64_t in_a[6] = {0xd7867eec22d47365, 0x9cc6812db2d6d04a,
                                     0x2bc0315620dd08ae, 0xc2248f1e1c5b3cc6,
                                     0xd6f2666aff9d26e3, 0x6f77cc3d984a4b9b};

    uint64_t out[12] = {0};

    static const uint8_t expected_out[96] = {
        0xD9, 0xE5, 0x4B, 0x27, 0x2E, 0x4D, 0xC5, 0xD1, 0xB9, 0x72, 0xD5, 0x7F,
        0x22, 0x50, 0xE6, 0x63, 0x28, 0xA6, 0xA1, 0x87, 0xDB, 0x20, 0x68, 0x94,
        0x5B, 0x3B, 0x5A, 0x3F, 0x58, 0xAC, 0x6C, 0xB2, 0x7B, 0x4D, 0x20, 0xD4,
        0x0B, 0x00, 0xAE, 0x20, 0x59, 0x24, 0x54, 0x21, 0x59, 0x77, 0x23, 0xBD,
        0x57, 0x26, 0x5C, 0x9C, 0x99, 0xE1, 0xF0, 0xB6, 0xF9, 0x5B, 0xB3, 0x0D,
        0x0C, 0x03, 0xB3, 0x7B, 0x9C, 0x45, 0x1A, 0x44, 0x49, 0x27, 0x46, 0x81,
        0x42, 0x52, 0x07, 0x32, 0x2F, 0xFD, 0x64, 0x3C, 0xC6, 0x0E, 0x90, 0x9F,
        0x5B, 0xC0, 0xC8, 0xC5, 0x2B, 0x3C, 0x46, 0xEE, 0x2C, 0x1B, 0x89, 0x30};

    result = soft_bignum_mult(&scl, in_a, in_a, out, 12);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

/* Right shift */
TEST(soft_bignumbers, soft_bignum_rightshift_size_0)
{
    int32_t retval = 0;
    uint64_t in[1] = {0xFFFFFFFFFFFFFFFFUL};
    uint64_t out[1] = {0};
    static const uint64_t expected_out[1] = {0};

    retval = soft_bignum_rightshift(NULL, in, out, 2, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_1)
{
    int32_t retval = 0;
    uint64_t in[1] = {0x00000000FFFFFFFFUL};
    uint64_t out[1] = {0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[1] = {0xFFFFFFFF3FFFFFFFUL};

    retval = soft_bignum_rightshift(NULL, in, out, 2, 1);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_2)
{
    int32_t retval = 0;
    uint64_t in[1] = {0xFFFFFFFFFFFFFFFFUL};
    uint64_t out[1] = {0};
    static const uint64_t expected_out[1] = {0x3FFFFFFFFFFFFFFFUL};

    retval = soft_bignum_rightshift(NULL, in, out, 2, 2);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_5)
{
    int32_t retval = 0;
    uint64_t in[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                      0x0FFFFFFFEFFFFFFFUL};
    uint64_t out[3] = {0, 0, 0x0FFFFFFF00000000UL};
    static const uint64_t expected_out[3] = {
        0xFFFFFFFFFFFFFFFFUL, 0x00000000EFFFFFFFUL, 0x0FFFFFFF00000000UL};

    retval = soft_bignum_rightshift(NULL, in, out, 64, 5);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_7)
{
    int32_t retval = 0;
    uint64_t in[4] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                      0xFFFFFFFFFFFFFFFFUL, 0x00000000EFFFFFFFUL};
    uint64_t out[4] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                       0xFFFFFFFFFFFFFFFFUL, 0x0FFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[4] = {
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0x0000000077FFFFFFUL,
        0x0FFFFFFF00000000UL};

    retval = soft_bignum_rightshift(NULL, in, out, 65, 7);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_5_shift_0)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x000000000FFFFFFFUL};
    uint64_t out[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {
        0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL, 0x000000000FFFFFFFUL};

    retval = soft_bignum_rightshift(NULL, in, out, 0, 5);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_5_shift_159)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x00000000FFFFFFFFUL};
    uint64_t out[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {1, 0, 0};

    retval = soft_bignum_rightshift(NULL, in, out, 159, 5);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_5_shift_1)
{
    int32_t retval = 0;
    uint64_t in[3] = {0xfdc343cbe8bc9306, 0x464cea82abecf963,
                      0xFFFFFFFF97c4844a};
    static const uint64_t expected_out[3] = {
        0xFEE1A1E5F45E4983, 0x2326754155F67CB1, 0xFFFFFFFF4BE24225};

    retval = soft_bignum_rightshift(&scl, in, in, 1, 5);

    TEST_ASSERT_TRUE(SCL_OK == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_5_shift_160)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x000000000FFFFFFFUL};
    uint64_t out[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {0, 0, 0};

    retval = soft_bignum_rightshift(NULL, in, out, 160, 5);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_5_in_NULL)
{
    int32_t retval = 0;
    uint64_t out[3] = {0, 0, 0};

    retval = soft_bignum_rightshift(NULL, NULL, out, 64, 5);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == retval);
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_5_out_NULL)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x000000000FFFFFFFUL};

    retval = soft_bignum_rightshift(NULL, in, NULL, 64, 5);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == retval);
}

TEST(soft_bignumbers, soft_bignum_rightshift_size_7_shift_59)
{
    int32_t retval = 0;
    uint64_t in[4] = {0x7800000000000000, 0x00091A2B3C4D5E6F, 0,
                      0xffffffff00000000};

    static const uint64_t expected_out[4] = {0x0123456789ABCDEF, 0, 0,
                                             0xffffffff00000000};

    retval = soft_bignum_rightshift(NULL, in, in, 59, 7);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

/* Left shift */
TEST(soft_bignumbers, soft_bignum_leftshift_size_0)
{
    int32_t retval = 0;
    uint64_t in[1] = {0xFFFFFFFFFFFFFFFFUL};
    uint64_t out[1] = {0};
    static const uint64_t expected_out[1] = {0};

    retval = soft_bignum_leftshift(NULL, in, out, 2, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_1)
{
    int32_t retval = 0;
    uint64_t in[1] = {0x000000000FFFFFFFUL};
    uint64_t out[1] = {0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[1] = {0xFFFFFFFF3FFFFFFCUL};

    retval = soft_bignum_leftshift(NULL, in, out, 2, 1);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_2)
{
    int32_t retval = 0;
    uint64_t in[1] = {0x0FFFFFFFFFFFFFFFUL};
    uint64_t out[1] = {0};
    static const uint64_t expected_out[1] = {0x3FFFFFFFFFFFFFFCUL};

    retval = soft_bignum_leftshift(NULL, in, out, 2, 2);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5)
{
    int32_t retval = 0;
    uint64_t in[3] = {0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFFUL,
                      0x0FFFFFFF0FFFFFFFUL};
    uint64_t out[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {0, 0xFFFFFFFF00000000UL,
                                             0x00000000FFFFFFFFUL};

    retval = soft_bignum_leftshift(NULL, in, out, 64, 5);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_7)
{
    int32_t retval = 0;
    uint64_t in[4] = {0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFFUL,
                      0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFFUL};
    uint64_t out[4] = {0, 0, 0, 0};
    static const uint64_t expected_out[4] = {
        0, 0xFFFFFFFE00000000UL, 0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFFUL};

    retval = soft_bignum_leftshift(NULL, in, out, 65, 7);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5_shift_0)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x000000000FFFFFFFUL};
    uint64_t out[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {
        0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL, 0x000000000FFFFFFFUL};

    retval = soft_bignum_leftshift(NULL, in, out, 0, 5);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5_shift_159)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x000000000FFFFFFFUL};
    uint64_t out[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {0, 0, 0x80000000};

    retval = soft_bignum_leftshift(NULL, in, out, 159, 5);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5_shift_1)
{
    int32_t retval = 0;
    uint64_t in[4] = {0xFFFFFFFFFFFFFFFF, 0xfdc343cbe8bc9306,
                      0x464cea82abecf963, 0xFFFFFFFF97c4844a};
    static const uint64_t expected_out[4] = {
        0xFFFFFFFFFFFFFFFF, 0xFB868797D179260C, 0x8C99D50557D9F2C7,
        0xFFFFFFFF2F890894};

    retval = soft_bignum_leftshift(&scl, &in[1], &in[1], 1, 5);

    TEST_ASSERT_TRUE(SCL_OK == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5_shift_160)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x000000000FFFFFFFUL};
    uint64_t out[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {0, 0, 0};

    retval = soft_bignum_leftshift(NULL, in, out, 160, 5);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5_in_NULL)
{
    int32_t retval = 0;
    uint64_t out[3] = {0, 0, 0};

    retval = soft_bignum_leftshift(NULL, NULL, out, 64, 5);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == retval);
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5_out_NULL)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0FFFFFFF0FFFFFFFUL, 0x0FFFFFFF0FFFFFFFUL,
                      0x000000000FFFFFFFUL};

    retval = soft_bignum_leftshift(NULL, in, NULL, 64, 5);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == retval);
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_7_shift_59)
{
    int32_t retval = 0;
    uint64_t in[4] = {0x0123456789ABCDEF, 0, 0, 0xffffffff00000000};
    static const uint64_t expected_out[4] = {
        0x7800000000000000, 0x00091A2B3C4D5E6F, 0, 0xffffffff00000000};

    retval = soft_bignum_leftshift(NULL, in, in, 59, 7);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_leftshift_size_5_shift_39)
{
    int32_t retval = 0;
    uint64_t in[3] = {0x0123456789ABCDEF, 0x0123456789ABCDEF,
                      0xFFFFFFFF00000000};
    static const uint64_t expected_out[3] = {
        0xD5E6F78000000000UL, 0xD5E6F78091A2B3C4UL, 0xFFFFFFFF91A2B3C4UL};

    retval = soft_bignum_leftshift(NULL, in, in, 39, 5);

    TEST_ASSERT_TRUE(0 == retval);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

/* test on msb set in word */
TEST(soft_bignumbers, soft_bignum_msb_set_in_word_32b_word)
{
    int32_t result = 0;
    uint32_t word = 0x80000000;

    result = soft_bignum_msb_set_in_word(word);

    TEST_ASSERT_TRUE(32 == result);
}

TEST(soft_bignumbers, soft_bignum_msb_set_in_word_64b_word_last_bit_set)
{
    int32_t result = 0;
    uint64_t word = 0x8000000000000000;

    result = soft_bignum_msb_set_in_word(word);

    TEST_ASSERT_TRUE(64 == result);
}

TEST(soft_bignumbers, soft_bignum_msb_set_in_word_64b_word_first_bit_set)
{
    int32_t result = 0;
    uint64_t word = 0x0000000000000001;

    result = soft_bignum_msb_set_in_word(word);

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_msb_set_in_word_32b_word_none_set)
{
    int32_t result = 0;
    uint32_t word[2] = {0x00000000, 0x00000001};

    result = soft_bignum_msb_set_in_word(word[0]);

    TEST_ASSERT_TRUE(0 == result);
}

/* test if bignumber is null */
TEST(soft_bignumbers, soft_bignum_is_null_size_6_lsb_set)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000};

    result = soft_bignum_is_null(NULL, (uint32_t *)array, 6);

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers, soft_bignum_is_null_size_6_msb_set)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x8000000000000000};

    result = soft_bignum_is_null(NULL, (uint32_t *)array, 6);

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers, soft_bignum_is_null_size_5_msb_set)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000080000000};

    result = soft_bignum_is_null(NULL, (uint32_t *)array, 5);

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers, soft_bignum_is_null_size_6_null)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000};

    result = soft_bignum_is_null(NULL, (uint32_t *)array, 6);

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_is_null_size_5_null)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000};

    result = soft_bignum_is_null(NULL, (uint32_t *)array, 5);

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_is_null_array_nullptr)
{
    int32_t result = 0;

    result = soft_bignum_is_null(NULL, NULL, 6);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
}

TEST(soft_bignumbers, soft_bignum_is_null_size_0)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000};

    result = soft_bignum_is_null(NULL, (uint32_t *)array, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
}

/* Get MSB set in bignumber */
TEST(soft_bignumbers, soft_bignum_get_msb_set_size_0)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000};

    result = soft_bignum_get_msb_set(NULL, array, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
}

TEST(soft_bignumbers, soft_bignum_get_msb_set_nullptr)
{
    int32_t result = 0;

    result = soft_bignum_get_msb_set(NULL, NULL, 6);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
}

TEST(soft_bignumbers, soft_bignum_get_msb_set_size_5_expect_1)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000};

    result = soft_bignum_get_msb_set(NULL, array, 5);

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_get_msb_set_size_5_expect_0)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000100000000};

    result = soft_bignum_get_msb_set(NULL, array, 5);

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers, soft_bignum_get_msb_set_size_5_expect_159)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000080000000};

    result = soft_bignum_get_msb_set(NULL, array, 5);

    TEST_ASSERT_TRUE(160 == result);
}

TEST(soft_bignumbers, soft_bignum_get_msb_set_size_5_124)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x1000000000000000,
                         0x0000000000000000};

    result = soft_bignum_get_msb_set(NULL, array, 5);

    TEST_ASSERT_TRUE(125 == result);
}

/* set one bit in a big integer */
TEST(soft_bignumbers, soft_bignum_set_bit_null_ptr)
{
    int32_t result = 0;

    result = soft_bignum_set_bit(NULL, NULL, 5, 1);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
}

TEST(soft_bignumbers, soft_bignum_set_bit_size_0)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x1000000000000000,
                         0x0000000000000000};

    result = soft_bignum_set_bit(NULL, array, 0, 1);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
}

TEST(soft_bignumbers, soft_bignum_set_bit_size_5_set_first)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000};
    uint64_t expected_array[3] = {0x0000000000000001, 0x0000000000000000,
                                  0x0000000000000000};

    result = soft_bignum_set_bit(NULL, array, 5, 0);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_array, array, sizeof(expected_array));
}

TEST(soft_bignumbers, soft_bignum_set_bit_size_5_set_last)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000};
    uint64_t expected_array[3] = {0x0000000000000000, 0x0000000000000000,
                                  0x0000000080000000};

    result = soft_bignum_set_bit(NULL, array, 5, 159);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_array, array, sizeof(expected_array));
}

TEST(soft_bignumbers, soft_bignum_set_bit_size_5_set_out_of_range)
{
    int32_t result = 0;
    uint64_t array[3] = {0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000};
    uint64_t expected_array[3] = {0x0000000000000000, 0x0000000000000000,
                                  0x0000000000000000};

    result = soft_bignum_set_bit(NULL, array, 5, 160);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_array, array, sizeof(expected_array));
}

/* Compare with different length */
TEST(soft_bignumbers, soft_bignum_compare_len_diff_a_equals_b)
{
    int32_t result = 0;
    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_a_greater_than_b_lsb)
{
    int32_t result = 0;

    static const uint64_t a[24] = {
        0xF2A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_a_greater_than_b_msb)
{
    int32_t result = 0;

    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3F798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_a_lower_than_b_lsb)
{
    int32_t result = 0;

    static const uint64_t a[24] = {
        0xF0A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(-1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_a_lower_than_b_msb)
{
    int32_t result = 0;

    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3D798BF33B755747UL,
    };

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(-1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_a_equals_b_len_a_greater)
{
    int32_t result = 0;
    static const uint64_t a[25] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000000UL};

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers,
     soft_bignum_compare_len_diff_a_greater_than_b_lsb_len_a_greater)
{
    int32_t result = 0;

    static const uint64_t a[25] = {
        0xF2A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000000UL};

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers,
     soft_bignum_compare_len_diff_a_lower_than_b_lsb_len_a_greater)
{
    int32_t result = 0;

    static const uint64_t a[25] = {
        0xF0A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000000UL};

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(-1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_a_equals_b_len_b_greater)
{
    int32_t result = 0;
    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[25] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000000UL};

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(0 == result);
}

TEST(soft_bignumbers,
     soft_bignum_compare_len_diff_a_greater_than_b_lsb_len_b_greater)
{
    int32_t result = 0;

    static const uint64_t a[24] = {
        0xF2A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[25] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000000UL};

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers,
     soft_bignum_compare_len_diff_a_lower_than_b_lsb_len_b_greater)
{
    int32_t result = 0;

    static const uint64_t a[24] = {
        0xF0A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[25] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000000UL};

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(-1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_len_a_greater)
{
    int32_t result = 0;
    static const uint64_t a[25] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000001UL};

    static const uint64_t b[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(1 == result);
}

TEST(soft_bignumbers, soft_bignum_compare_len_diff_len_b_greater)
{
    int32_t result = 0;
    static const uint64_t a[24] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
    };

    static const uint64_t b[25] = {
        0xF1A731C16826B112UL, 0xC2D6C36F322ADB31UL, 0xADF814D04293621AUL,
        0x99257956ACB04888UL, 0x213CB160A56E652BUL, 0x5EA07B4C36F5E742UL,
        0x7C6EA7AFFD28FD8CUL, 0x60A8B22AC65FF673UL, 0x35299037A28056EEUL,
        0xA6396CA2E6D640CAUL, 0x1BAACCE52D040622UL, 0x780D9E8F08E3822EUL,
        0x67EF2D9DD4D5E501UL, 0x62EE9A2018317A61UL, 0xFB1B54732E3EA55FUL,
        0x31B582608D37B9AEUL, 0xE661A5C8F4AFCDADUL, 0x6FB02950DC6A0F66UL,
        0x47FE18A5DA8C7F52UL, 0x9C0BB95DD4E9D4ABUL, 0xBB734830CFEAE7A3UL,
        0x96F63E471BF5B240UL, 0xAB08087F8E40F50FUL, 0x3E798BF33B755747UL,
        0x0000000000000001UL};

    result = soft_bignum_compare_len_diff(NULL, a, NB_32BITS_WORDS(a),
                                          b, NB_32BITS_WORDS(b));

    TEST_ASSERT_TRUE(-1 == result);
}

/* big integer division */
TEST(soft_bignumbers, soft_bignum_div_by_0)
{
    int32_t result = 0;
    uint64_t dividend[6] = {0x0000000000000001, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t divisor[3] = {0x0000000000000000, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t quotient[6] = {0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_quotient[6] = {0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result = soft_bignum_div(
        &scl, dividend, NB_32BITS_WORDS(dividend), divisor,
        NB_32BITS_WORDS(divisor), remainder, quotient);

    TEST_ASSERT_TRUE(SCL_ZERO_DIVISION == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_quotient, quotient,
                                 sizeof(expected_quotient));
}

TEST(soft_bignumbers, soft_bignum_div_dividend_null_ptr)
{
    int32_t result = 0;
    uint64_t dividend[6] = {0x0000000000000001, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t divisor[3] = {0x0000000000000000, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t quotient[6] = {0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_quotient[6] = {0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result = soft_bignum_div(&scl, NULL, NB_32BITS_WORDS(dividend),
                             divisor, NB_32BITS_WORDS(divisor),
                             remainder, quotient);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_quotient, quotient,
                                 sizeof(expected_quotient));
}

TEST(soft_bignumbers, soft_bignum_div_divisor_null_ptr)
{
    int32_t result = 0;
    uint64_t dividend[6] = {0x0000000000000001, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t divisor[3] = {0x0000000000000001, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t quotient[6] = {0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_quotient[6] = {0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result = soft_bignum_div(
        &scl, dividend, NB_32BITS_WORDS(dividend), NULL,
        NB_32BITS_WORDS(divisor), remainder, quotient);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_quotient, quotient,
                                 sizeof(expected_quotient));
}

TEST(soft_bignumbers, soft_bignum_div_dividend_size_0)
{
    int32_t result = 0;
    uint64_t dividend[6] = {0x0000000000000001, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t divisor[3] = {0x0000000000000001, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t quotient[6] = {0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_quotient[6] = {0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result = soft_bignum_div(&scl, dividend, 0, divisor, NB_32BITS_WORDS(divisor), remainder,
                             quotient);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_quotient, quotient,
                                 sizeof(expected_quotient));
}

TEST(soft_bignumbers, soft_bignum_div_divisor_size_0)
{
    int32_t result = 0;
    uint64_t dividend[6] = {0x0000000000000001, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t divisor[3] = {0x0000000000000001, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t quotient[6] = {0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_quotient[6] = {0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000,
                                     0x0000000000000000, 0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result =
        soft_bignum_div(&scl, dividend, NB_32BITS_WORDS(dividend),
                        divisor, 0, remainder, quotient);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_quotient, quotient,
                                 sizeof(expected_quotient));
}

TEST(soft_bignumbers, soft_bignum_div_dividend_lt_divisor)
{
    int32_t result = 0;
    uint64_t dividend[6] = {
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xEFFFFFFFFFFFFFFF, 0, 0, 0};
    uint64_t divisor[3] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                           0xFFFFFFFFFFFFFFFF};
    uint64_t quotient[6] = {0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000,
                            0x0000000000000000, 0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_quotient[6] = {0, 0, 0, 0, 0, 0};
    uint64_t expected_remainder[3] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                      0xEFFFFFFFFFFFFFFF};

    result = soft_bignum_div(
        &scl, dividend, NB_32BITS_WORDS(dividend), divisor,
        NB_32BITS_WORDS(divisor), remainder, quotient);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_quotient, quotient,
                                 sizeof(expected_quotient));
}

TEST(soft_bignumbers, soft_bignum_div_dividend_gt_divisor)
{
    int32_t result = 0;
    uint64_t dividend[6] = {0x0FFFFFFFFFFFFFFF, 0, 0, 0, 0, 0};
    uint64_t divisor[3] = {0x0123456789ABCDEF, 0, 0};
    uint64_t quotient[6] = {0, 0, 0, 0, 0, 0};
    uint64_t remainder[3] = {0, 0, 0};

    uint64_t expected_quotient[6] = {0x0E, 0, 0, 0, 0, 0};
    uint64_t expected_remainder[3] = {0x0123456789ABCED, 0, 0};

    result = soft_bignum_div(
        &scl, dividend, NB_32BITS_WORDS(dividend), divisor,
         NB_32BITS_WORDS(divisor), remainder, quotient);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_quotient, quotient,
                                 sizeof(expected_quotient));
}

/* modulus computation */
TEST(soft_bignumbers, soft_bignum_mod_modulus_0)
{
    int32_t result = 0;
    uint64_t input[6] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000};
    uint64_t modulus[3] = {0x0000000000000000, 0x0000000000000000,
                           0x0000000000000000};

    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result =
        soft_bignum_mod(&scl, input, NB_32BITS_WORDS(input), modulus,
                        NB_32BITS_WORDS(modulus), remainder);

    TEST_ASSERT_TRUE(SCL_ZERO_DIVISION == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_input_null_ptr)
{
    int32_t result = 0;
    uint64_t input[6] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000};
    uint64_t modulus[3] = {0x0000000000000000, 0x0000000000000000,
                           0x0000000000000000};

    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};

    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result =
        soft_bignum_mod(&scl, NULL, NB_32BITS_WORDS(input), modulus,
                        NB_32BITS_WORDS(modulus), remainder);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_modulus_null_ptr)
{
    int32_t result = 0;
    uint64_t input[6] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000};
    uint64_t modulus[3] = {0x0000000000000001, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result =
        soft_bignum_mod(&scl, input, NB_32BITS_WORDS(input), NULL,
                        NB_32BITS_WORDS(modulus), remainder);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_input_size_0)
{
    int32_t result = 0;
    uint64_t input[6] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000};
    uint64_t modulus[3] = {0x0000000000000001, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result = soft_bignum_mod(&scl, input, 0, modulus,
                             NB_32BITS_WORDS(modulus), remainder);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_modulus_size_0)
{
    int32_t result = 0;
    uint64_t input[6] = {0x0000000000000001, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000,
                         0x0000000000000000, 0x0000000000000000};
    uint64_t modulus[3] = {0x0000000000000001, 0x0000000000000000,
                           0x0000000000000000};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};
    uint64_t expected_remainder[3] = {0x0000000000000000, 0x0000000000000000,
                                      0x0000000000000000};

    result = soft_bignum_mod(&scl, input, NB_32BITS_WORDS(input),
                             modulus, 0, remainder);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_input_lt_modulus)
{
    int32_t result = 0;
    uint64_t input[6] = {
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xEFFFFFFFFFFFFFFF, 0, 0, 0};
    uint64_t modulus[3] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                           0xFFFFFFFFFFFFFFFF};
    uint64_t remainder[3] = {0x0000000000000000, 0x0000000000000000,
                             0x0000000000000000};
    uint64_t expected_remainder[3] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                      0xEFFFFFFFFFFFFFFF};

    result =
        soft_bignum_mod(&scl, input, NB_32BITS_WORDS(input), modulus,
                        NB_32BITS_WORDS(modulus), remainder);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_input_gt_modulus)
{
    int32_t result = 0;
    uint64_t input[6] = {0x0FFFFFFFFFFFFFFF, 0, 0, 0, 0, 0};
    uint64_t modulus[3] = {0x0123456789ABCDEF, 0, 0};
    uint64_t remainder[3] = {0, 0, 0};

    uint64_t expected_remainder[3] = {0x0123456789ABCED, 0, 0};

    result =
        soft_bignum_mod(&scl, input, NB_32BITS_WORDS(input), modulus,
                        NB_32BITS_WORDS(modulus), remainder);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_input_gt_modulus_2)
{
    int32_t result = 0;
    uint64_t input[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                         0x00000000FFFFFFFFUL};
    uint64_t modulus[2] = {0x0123456789ABCDEFUL, 0x0123456789ABCDEFUL};
    uint64_t remainder[2] = {0, 0};
    uint64_t expected_remainder[2] = {0x000000F0FFFFFFFFUL, 0x000000F000000000};

    result =
        soft_bignum_mod(&scl, input, NB_32BITS_WORDS(input), modulus,
                        NB_32BITS_WORDS(modulus), remainder);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

TEST(soft_bignumbers, soft_bignum_mod_size_12)
{
    int32_t result = 0;

    static const uint8_t in[96] __attribute__((aligned(8))) = {
        0xD9, 0xE5, 0x4B, 0x27, 0x2E, 0x4D, 0xC5, 0xD1, 0xB9, 0x72, 0xD5, 0x7F,
        0x22, 0x50, 0xE6, 0x63, 0x28, 0xA6, 0xA1, 0x87, 0xDB, 0x20, 0x68, 0x94,
        0x5B, 0x3B, 0x5A, 0x3F, 0x58, 0xAC, 0x6C, 0xB2, 0x7B, 0x4D, 0x20, 0xD4,
        0x0B, 0x00, 0xAE, 0x20, 0x59, 0x24, 0x54, 0x21, 0x59, 0x77, 0x23, 0xBD,
        0x57, 0x26, 0x5C, 0x9C, 0x99, 0xE1, 0xF0, 0xB6, 0xF9, 0x5B, 0xB3, 0x0D,
        0x0C, 0x03, 0xB3, 0x7B, 0x9C, 0x45, 0x1A, 0x44, 0x49, 0x27, 0x46, 0x81,
        0x42, 0x52, 0x07, 0x32, 0x2F, 0xFD, 0x64, 0x3C, 0xC6, 0x0E, 0x90, 0x9F,
        0x5B, 0xC0, 0xC8, 0xC5, 0x2B, 0x3C, 0x46, 0xEE, 0x2C, 0x1B, 0x89, 0x30};

    uint64_t remainder[6] = {0, 0};
    static const uint8_t expected_remainder[48] = {
        0x25, 0xc0, 0x77, 0xf8, 0x02, 0x51, 0x99, 0x6b, 0xeb, 0x47, 0x58, 0x41,
        0x55, 0x95, 0xcb, 0xb4, 0xf8, 0x85, 0xab, 0x5b, 0xfb, 0x93, 0x16, 0x69,
        0xe0, 0x37, 0xda, 0xc8, 0x1a, 0xbb, 0x20, 0xad, 0xf8, 0xcb, 0xab, 0xfc,
        0x2c, 0x2b, 0x34, 0xfa, 0x9a, 0xef, 0x3d, 0xb8, 0x4f, 0x62, 0x5b, 0xdb};

    result = soft_bignum_mod(&scl, (const uint64_t *)in, 24, ecc_secp384r1.p,
                             12, remainder);

    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_remainder, remainder,
                                 sizeof(expected_remainder));
}

/* Modular addition */
TEST(soft_bignumbers, soft_bignum_mod_add_size_0)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_add(&scl, &bignum_ctx, &in_a, &in_b, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_add_size_1)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF77777777UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_add(&scl, &bignum_ctx, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_add_size_1_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF77777778UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_add(&scl, &bignum_ctx, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_add_size_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFFUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0x0000000077777778UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_add(&scl, &bignum_ctx, &in_a, &in_b, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_add_size_2_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0x0000000077777778UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_add(&scl, &bignum_ctx, &in_a, &in_b, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_add_size_5)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                     0x0000000032DD71F1UL};
    static const uint64_t in_b[3] = {0xB8ADBD61E64C509EUL, 0x313F0EA554C0D0DEUL,
                                     0x000000001BED89D1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x00000000CAA1F63BUL};
    static const uint64_t expected_out[3] = {
        0x1D38CD1C172414C9UL, 0x90BEAA35CCE917E8UL, 0xFFFFFFFF4ECAFBC2UL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_add(&scl, &bignum_ctx, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_mod_add_size_5_2)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                     0x0000000032DD71F1UL};
    static const uint64_t in_b[3] = {0xB8ADBD61E64C509EUL, 0x313F0EA554C0D0DEUL,
                                     0x000000001BED89D1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x0000000000A1F63BUL};
    static const uint64_t expected_out[3] = {
        0x7F485827B349D815UL, 0x41ADB8F0529DE2ECUL, 0xFFFFFFFF0057B6DEUL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_add(&scl, &bignum_ctx, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

/* Negate */
TEST(soft_bignumbers, soft_bignum_negate_size_0)
{
    int32_t result = 0;

    uint64_t in = 0x00000000FFFFFFFFUL;
    static const uint64_t expected_out = 0x00000000FFFFFFFFUL;

    result = soft_bignum_negate(&scl, &in, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_negate_nullptr)
{
    int32_t result = 0;

    uint64_t in = 0x00000000FFFFFFFFUL;
    static const uint64_t expected_out = 0x00000000FFFFFFFFUL;

    result = soft_bignum_negate(&scl, NULL, 1);

    TEST_ASSERT_TRUE(SCL_INVALID_INPUT == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_negate_size_1)
{
    int32_t result = 0;

    uint64_t in = 0x00000000FFFFFFFEUL;
    static const uint64_t expected_out = 2;

    result = soft_bignum_negate(&scl, &in, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_negate_size_1_2)
{
    int32_t result = 0;

    uint64_t in = 0x00000000FFFFFFF0UL;
    static const uint64_t expected_out = 16;

    result = soft_bignum_negate(&scl, &in, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == in);
}

TEST(soft_bignumbers, soft_bignum_negate_size_5)
{
    int32_t result = 0;
    uint64_t in[3] = {0, 0, 0};
    static const uint64_t expected_out[3] = {0, 0, 0};

    result = soft_bignum_negate(&scl, in, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_negate_size_5_2)
{
    int32_t result = 0;
    uint64_t in[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                      0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[3] = {1, 0, 0xFFFFFFFF00000000UL};

    result = soft_bignum_negate(&scl, in, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, in, sizeof(expected_out));
}

/* Modular subtraction */
TEST(soft_bignumbers, soft_bignum_mod_sub_size_0)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, &in_a, &in_b, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_sub_size_1)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF77777775UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_sub_size_1_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 1;
    static const uint64_t in_b = 2;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF88888887UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_sub_size_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFFUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0x0000000077777776UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, &in_a, &in_b, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_sub_size_2_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 1;
    static const uint64_t in_b = 2;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0x0000000088888887UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, &in_a, &in_b, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_sub_size_2_3)
{
    int32_t result = 0;

    static const uint64_t in_a = 0;
    static const uint64_t in_b = 0x00000000FFFFFFFFUL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0x0000000011111111UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, &in_a, &in_b, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_sub_size_5)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                     0x0000000032DD71F1UL};
    static const uint64_t in_b[3] = {0xB8ADBD61E64C509EUL, 0x313F0EA554C0D0DEUL,
                                     0x000000001BED89D1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x00000000CAA1F63BUL};
    static const uint64_t expected_out[3] = {
        0xABDD52584A8B738DUL, 0x2E408CEB2367762AUL, 0xFFFFFFFF16EFE820UL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_mod_sub_size_5_2)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                     0x0000000032DD71F1UL};
    static const uint64_t in_b[3] = {0xB8ADBD61E64C509EUL, 0x313F0EA554C0D0DEUL,
                                     0x000000001BED89D1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x0000000000A1F63BUL};
    static const uint64_t expected_out[3] = {
        0xD8D9937CB1AF3061UL, 0xDD7DB23A106A66C8UL, 0xFFFFFFFF002947BCUL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_sub(&scl, &bignum_ctx, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

/* Negate mod */
TEST(soft_bignumbers, soft_bignum_mod_neg_size_0)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFFFFFFFFFEUL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_neg(&scl, &bignum_ctx, &in, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_neg_size_1)
{
    int32_t result = 0;

    static const uint64_t in = 0x00000000FFFFFFFEUL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF11111112UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_neg(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_neg_size_1_2)
{
    int32_t result = 0;

    static const uint64_t in = 1;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF88888887UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_neg(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_neg_size_2)
{
    int32_t result = 0;

    static const uint64_t in = 0;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888844UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_neg(&scl, &bignum_ctx, &in, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_neg_size_2_2)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFFFFFFFFFFUL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888844UL;
    static const uint64_t expected_out = 0x0000000008884805UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_neg(&scl, &bignum_ctx, &in, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_neg_size_5)
{
    int32_t result = 0;

    static const uint64_t in[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                   0x0000000032DD71F1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x00000000CAA1F63BUL};
    static const uint64_t expected_out[3] = {
        0xFDC343CBE8BC9308, 0x464CEA82ABECF963, 0xFFFFFFFF97C4844AUL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_neg(&scl, &bignum_ctx, in, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_mod_neg_size_5_2)
{
    int32_t result = 0;

    static const uint64_t in[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                   0x0000000032DD71F1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x0000000000A1F63BUL};
    static const uint64_t expected_out[3] = {
        0xB63D5DB3E717D2F8UL, 0x1636D07DF2911B92UL, 0xFFFFFFFF006176EEUL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_neg(&scl, &bignum_ctx, in, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

/* Modular multiplication */
TEST(soft_bignumbers, soft_bignum_mod_mult_size_0)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFEUL;
    static const uint64_t in_b = 1;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, &in_a, &in_b, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_mult_size_1)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x00000000FFFFFFFEUL;
    static const uint64_t in_b = 0;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888844UL;
    static const uint64_t expected_out = 0xFFFFFFFF00000000UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_mult_size_1_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFF88888887UL;
    static const uint64_t in_b = 1;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF88888887UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, &in_a, &in_b, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_mult_size_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t in_b = 0xFFFFFFFFFFFFFFFFUL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000008888888844UL;
    static const uint64_t expected_out = 0x00000087A7E8E865UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, &in_a, &in_b, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_mult_size_2_2)
{
    int32_t result = 0;

    static const uint64_t in_a = 0x0000008888888844UL;
    static const uint64_t in_b = 0x000000FFFFFFFF04UL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000008888888844UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, &in_a, &in_b, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_mult_size_5)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                     0x0000000032DD71F1UL};
    static const uint64_t in_b[3] = {0xB8ADBD61E64C509EUL, 0x313F0EA554C0D0DEUL,
                                     0x000000001BED89D1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x00000000CAA1F63BUL};
    static const uint64_t expected_out[3] = {
        0x8CA81DFF74110FDFUL, 0x23784294875967CAUL, 0xFFFFFFFF3445E07AUL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_mod_mult_size_5_2)
{
    int32_t result = 0;

    static const uint64_t in_a[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                     0x0000000032DD71F1UL};
    static const uint64_t in_b[3] = {0xB8ADBD61E64C509EUL, 0x313F0EA554C0D0DEUL,
                                     0x000000001BED89D1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x0000000000A1F63BUL};
    static const uint64_t expected_out[3] = {
        0xF3E059F6C1FD3BA8UL, 0xE27C4581A326DFD7UL, 0xFFFFFFFF009F07C0UL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, in_a, in_b, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_mod_mult_size_12)
{
    int32_t result = 0;

    static const uint8_t in_a[48] __attribute__((aligned(8))) = {
        0x69, 0xfa, 0x31, 0x41, 0x03, 0xc7, 0x19, 0x89, 0x95, 0x05, 0x80, 0x81,
        0x6c, 0xe6, 0x99, 0x4b, 0x99, 0xf7, 0x9e, 0x12, 0x59, 0x84, 0xb0, 0x3a,
        0xd8, 0xfa, 0x7a, 0x70, 0x0c, 0x88, 0xda, 0xfc, 0x7a, 0x99, 0x70, 0x0b,
        0xc5, 0xce, 0x3b, 0xe7, 0x54, 0x9e, 0x45, 0xf6, 0x27, 0x23, 0x56, 0x40};

    static const uint8_t in_b[48] __attribute__((aligned(8))) = {
        0x94, 0x68, 0xbc, 0x90, 0xc8, 0x9f, 0x23, 0xe8, 0x87, 0x0d, 0xae, 0x31,
        0xef, 0xf3, 0x1e, 0xc6, 0xbe, 0x84, 0x96, 0xa5, 0x6c, 0x23, 0xad, 0xc5,
        0x7a, 0x7e, 0x04, 0x75, 0xeb, 0xe4, 0xbc, 0xba, 0x63, 0xc0, 0x0c, 0x90,
        0x48, 0x88, 0x5a, 0xa7, 0x20, 0x27, 0xcc, 0x8c, 0xc9, 0xb3, 0x11, 0xa0};

    uint8_t out[48] __attribute__((aligned(8))) = {0};

    static const uint8_t modulus[48] __attribute__((aligned(8))) = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    static const uint8_t expected_out[48] = {
        0x16, 0xB1, 0x59, 0x5C, 0x8C, 0x15, 0x36, 0x26, 0x5D, 0x56, 0xFE, 0x99,
        0x43, 0xD1, 0x56, 0xD0, 0x73, 0x09, 0xC5, 0x19, 0x02, 0x35, 0x0F, 0xE2,
        0xAD, 0x74, 0x98, 0xE2, 0x6A, 0xCC, 0x8B, 0xDB, 0x71, 0xDA, 0x71, 0x58,
        0x85, 0xB1, 0x35, 0xCC, 0x3A, 0x64, 0x1C, 0xB6, 0xA9, 0x80, 0xFA, 0xB0};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx,
                                     (const uint64_t *)modulus, 12);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_mult(&scl, &bignum_ctx, (const uint64_t *)in_a,
                                  (const uint64_t *)in_b, (uint64_t *)out, 12);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

/* Modular multiplicative inverse */
TEST(soft_bignumbers, soft_bignum_mod_inv_size_0)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFFFFFFFFFEUL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888889UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, &in, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_1_not_inversible)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFF88888887UL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x00000000FFFFFFFFUL;
    static const uint64_t expected_out = 0xFFFFFFFFFFFFFFFFUL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_NOT_INVERSIBLE == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_1_err_parity)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFF88888887UL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x00000000FFFFFFFEUL;
    static const uint64_t expected_out = 0xFFFFFFFFFFFFFFFFUL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_ERR_PARITY == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_1)
{
    int32_t result = 0;

    static const uint64_t in = 0x00000000FFFFFFFDUL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888845UL;
    static const uint64_t expected_out = 0xFFFFFFFF50354995UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_1_2)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFF88888886UL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x00000000FFFFFFFFUL;
    static const uint64_t expected_out = 0xFFFFFFFFA2222221UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_2)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFFFFFFFFFFUL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000008888888845UL;
    static const uint64_t expected_out = 0x00000070EEB6AF96UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, &in, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_2_2)
{
    int32_t result = 0;

    static const uint64_t in = 2;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000008888888843UL;
    static const uint64_t expected_out = 0x4444444422;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, &in, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_5)
{
    int32_t result = 0;

    static const uint64_t in[3] = {0x648B0FBA30D7C42DUL, 0x5F7F9B9078284709UL,
                                   0x0000000032DD71F1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x00000000CAA1F63BUL};
    static const uint64_t expected_out[3] = {
        0x0A1C1BC96863458BUL, 0x07E1D6FD8C65C70EUL, 0xFFFFFFFF65D410E7UL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, in, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_5_2)
{
    int32_t result = 0;

    static const uint64_t in[3] = {0x648B0FBA30D7C42CUL, 0x5F7F9B9078284709UL,
                                   0x0000000032DD71F1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x0000000000A1F63BUL};
    static const uint64_t expected_out[3] = {
        0x10BFDB5C5FFB631E, 0x1B15C9BF2797CBB0UL, 0xFFFFFFFF0052431AUL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, in, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

TEST(soft_bignumbers, soft_bignum_mod_inv_size_5_not_inversible)
{
    int32_t result = 0;

    static const uint64_t in[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                   0x0000000032DD71F1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x0000000000A1F63BUL};
    static const uint64_t expected_out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_inv(&scl, &bignum_ctx, in, out, 5);

    TEST_ASSERT_TRUE(SCL_NOT_INVERSIBLE == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}

/* square */
TEST(soft_bignumbers, soft_bignum_square_size_0)
{
    int32_t result = 0;
    static const uint64_t in = 0xFFFFFFFFFFFFFFFEUL;
    uint64_t out[2] = {0};
    static const uint64_t expected_out[2] = {0};

    result = soft_bignum_square(NULL, &in, out, 0);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
}

TEST(soft_bignumbers, soft_bignum_square_size_1)
{
    int32_t result = 0;
    static const uint64_t in = 0x00000000FFFFFFFFUL;
    uint64_t out = 0;
    static const uint64_t expected_out = 0xFFFFFFFE00000001UL;

    result = soft_bignum_square(NULL, &in, &out, 1);

    TEST_ASSERT_TRUE(expected_out == out);
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_square_size_2)
{
    int32_t result = 0;
    static const uint64_t in = 0xFFFFFFFFFFFFFFFFUL;
    uint64_t out[2] = {0};
    static const uint64_t expected_out[2] = {0x0000000000000001UL,
                                             0xFFFFFFFFFFFFFFFEUL};

    result = soft_bignum_square(NULL, &in, out, NB_32BITS_WORDS(in));

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_square_size_5)
{
    int32_t result = 0;
    static const uint64_t in[3] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                                   0x00000000FFFFFFFFUL};

    uint64_t out[5] = {0};
    static const uint64_t expected_out[5] = {
        0x0000000000000001UL, 0x0000000000000000UL, 0xFFFFFFFE00000000UL,
        0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL};

    result = soft_bignum_square(NULL, in, out, 5);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(soft_bignumbers, soft_bignum_square_size_5_zero)
{
    int32_t result = 0;
    static const uint64_t in[3] = {0, 0, 0};

    uint64_t out[5] = {0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                       0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
                       0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t expected_out[5] = {0, 0, 0, 0, 0};

    result = soft_bignum_square(NULL, in, out, 5);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
    TEST_ASSERT_TRUE(SCL_OK == result);
}

/* Modular square */
TEST(soft_bignumbers, soft_bignum_mod_square_size_0)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFFFFFFFFFEUL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_square(&scl, &bignum_ctx, &in, &out, 0);

    TEST_ASSERT_TRUE(SCL_INVALID_LENGTH == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_square_size_1)
{
    int32_t result = 0;

    static const uint64_t in = 0;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888844UL;
    static const uint64_t expected_out = 0xFFFFFFFF00000000UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_square(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_square_size_1_2)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFF00000001UL;
    uint64_t out = 0xFFFFFFFFFFFFFFFFUL;
    static const uint64_t modulus = 0x0000000088888888UL;
    static const uint64_t expected_out = 0xFFFFFFFF00000001UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_square(&scl, &bignum_ctx, &in, &out, 1);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_square_size_2)
{
    int32_t result = 0;

    static const uint64_t in = 0xFFFFFFFFFFFFFFFFUL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000008888888844UL;
    static const uint64_t expected_out = 0x00000087A7E8E865UL;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_square(&scl, &bignum_ctx, &in, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_square_size_2_2)
{
    int32_t result = 0;

    static const uint64_t in = 0x0000008888888844UL;
    uint64_t out = 0;
    static const uint64_t modulus = 0x0000008888888844UL;
    static const uint64_t expected_out = 0;

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, &modulus, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_square(&scl, &bignum_ctx, &in, &out, 2);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_TRUE(expected_out == out);
}

TEST(soft_bignumbers, soft_bignum_mod_square_size_5)
{
    int32_t result = 0;

    static const uint64_t in[3] = {0x648B0FBA30D7C42BUL, 0x5F7F9B9078284709UL,
                                   0x0000000032DD71F1UL};
    uint64_t out[3] = {0, 0, 0xFFFFFFFFFFFFFFFFUL};
    static const uint64_t modulus[3] = {
        0x624E538619945733UL, 0xA5CC86132415406DUL, 0x00000000CAA1F63BUL};
    static const uint64_t expected_out[3] = {
        0xA5B61FF63ABDCDACUL, 0xC058A2976C4F1D7EUL, 0xFFFFFFFF071E8973UL};

    bignum_ctx_t bignum_ctx;

    memset(&bignum_ctx, 0, sizeof(bignum_ctx));

    result = soft_bignum_set_modulus(&scl, &bignum_ctx, modulus, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);

    result = soft_bignum_mod_square(&scl, &bignum_ctx, in, out, 5);

    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_out, out, sizeof(expected_out));
}
