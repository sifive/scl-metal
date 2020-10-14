/**
 * @file test_scl_aes_128.c
 * @brief test suite for scl_aes_{cbc, ccm, cfb, ctr, ecb, gcm, ofb}.c on 192
 * bits key length
 * @note These tests use HCA (Hardware Cryptographic Accelerator)
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

#include <string.h>

#include <backend/api/scl_backend_api.h>

#include <scl/scl_selftests.h>

#include <scl/scl_ecdsa.h>
#include <scl/scl_sha.h>

#include <backend/api/hash/sha/sha.h>
#include <backend/software/scl_soft.h>

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
    .hash_func =
        {
            .sha_init = soft_sha_init,
            .sha_core = soft_sha_core,
            .sha_finish = soft_sha_finish,
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
            .leftshift = soft_bignum_leftshift,
            .rightshift = soft_bignum_rightshift,
            .msb_set_in_word = soft_bignum_msb_set_in_word,
            .get_msb_set = soft_bignum_get_msb_set,
            .set_bit = soft_bignum_set_bit,
            .div = soft_bignum_div,
            .mod = soft_ecc_mod,
            .set_modulus = soft_bignum_set_modulus,
            .mod_add = soft_bignum_mod_add,
            .mod_sub = soft_bignum_mod_sub,
            .mod_mult = soft_bignum_mod_mult,
            .mod_inv = soft_bignum_mod_inv,
            .mod_square = soft_bignum_mod_square,
        },

    .ecdsa_func =
        {
            .signature = soft_ecdsa_signature,
            .verification = soft_ecdsa_verification,
        },
};

int32_t get_data_for_test(const metal_scl_t *const scl_ctx, uint32_t *data_out)
{
    (void)scl_ctx;
    *data_out = 0xA5A5A5A5;
    return (SCL_OK);
}

TEST_GROUP(scl_selftests);

TEST_SETUP(scl_selftests) {}

TEST_TEAR_DOWN(scl_selftests) {}

TEST(scl_selftests, scl_ecdsa_p256r1_sha256_selftest)
{
    int32_t result = 0;

    result = scl_ecdsa_p256r1_sha256_selftest(&scl);

    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(scl_selftests, scl_ecdsa_p384r1_sha384_selftest)
{
    int32_t result = 0;

    result = scl_ecdsa_p384r1_sha384_selftest(&scl);

    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(scl_selftests, scl_ecdsa_p521r1_sha512_selftest)
{
    int32_t result = 0;

    result = scl_ecdsa_p521r1_sha512_selftest(&scl);

    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(scl_selftests, scl_hash_sha256_selftest)
{
    int32_t result = 0;

    result = scl_hash_sha256_selftest(&scl);

    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(scl_selftests, scl_hash_sha384_selftest)
{
    int32_t result = 0;

    result = scl_hash_sha384_selftest(&scl);

    TEST_ASSERT_TRUE(SCL_OK == result);
}

TEST(scl_selftests, scl_hash_sha512_selftest)
{
    int32_t result = 0;

    result = scl_hash_sha512_selftest(&scl);

    TEST_ASSERT_TRUE(SCL_OK == result);
}
