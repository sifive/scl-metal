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
#include <scl/scl_trng.h>

#include <backend/hardware/scl_hca.h>

#include  <metal/machine/platform.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)

static const metal_scl_t scl = {
    .hca_base = METAL_SIFIVE_HCA_0_BASE_ADDRESS,
    .trng_func = {.init = hca_trng_init,
                 .get_data = hca_trng_getdata,}};

TEST_GROUP_RUNNER(scl_trng)
{
    RUN_TEST_CASE(scl_trng, simple_test);
}

TEST_GROUP(scl_trng);

TEST_SETUP(scl_trng) {}

TEST_TEAR_DOWN(scl_trng) {}

TEST(scl_trng, simple_test)
{
    uint8_t tmp[64] = {0};
    int32_t result = 0;
    size_t i;

    result = scl_trng_init(&scl);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = scl_trng_get_data(&scl, tmp, sizeof(tmp));
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = 0;
    for (i = 0; i < sizeof(tmp); i++) {
        if(0 != tmp[i]) {
            result += 1;
        }
    }
    TEST_ASSERT_TRUE(0 != result);
}

#endif
