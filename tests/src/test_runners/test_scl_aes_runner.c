/**
 * @file test_scl_aes_runner.c
 * @brief test runner for test_scl_aes.c
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity.h"
#include "unity_fixture.h"

#include <api/hardware/scl_hca.h>
#include <metal/machine/platform.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)

// AES 128
TEST_GROUP_RUNNER(scl_aes_128)
{
    RUN_TEST_CASE(scl_aes_128, ecb_F_1_12);
    RUN_TEST_CASE(scl_aes_128, ecb_F_1_12_high);
    RUN_TEST_CASE(scl_aes_128, ecb_not_aligned);
    RUN_TEST_CASE(scl_aes_128, cbc_F_2_12);
    RUN_TEST_CASE(scl_aes_128, cbc_F_2_12_high);
    RUN_TEST_CASE(scl_aes_128, cfb_F_3_1314);
    RUN_TEST_CASE(scl_aes_128, ofb_F_4_12);
    RUN_TEST_CASE(scl_aes_128, ctr_F_5_12);
    RUN_TEST_CASE(scl_aes_128, ccm_1);
    RUN_TEST_CASE(scl_aes_128, ccm_2);
    RUN_TEST_CASE(scl_aes_128, ccm_3);
    RUN_TEST_CASE(scl_aes_128, ccm_4);
    RUN_TEST_CASE(scl_aes_128, gcm_1);
    RUN_TEST_CASE(scl_aes_128, gcm_1_b1);
    RUN_TEST_CASE(scl_aes_128, gcm_2);
    RUN_TEST_CASE(scl_aes_128, gcm_3);
    RUN_TEST_CASE(scl_aes_128, gcm_3_b1);
    RUN_TEST_CASE(scl_aes_128, gcm_3_b2);
    RUN_TEST_CASE(scl_aes_128, gcm_3_b3);
}

// AES 192
TEST_GROUP_RUNNER(scl_aes_192)
{
    RUN_TEST_CASE(scl_aes_192, ecb_F_1_34);
    RUN_TEST_CASE(scl_aes_192, ecb_F_1_34_high);
    RUN_TEST_CASE(scl_aes_192, cbc_F_2_34);
    RUN_TEST_CASE(scl_aes_192, cbc_F_2_34_high);
}

// AES 256
TEST_GROUP_RUNNER(scl_aes_256)
{
    RUN_TEST_CASE(scl_aes_256, ecb_F_1_56);
    RUN_TEST_CASE(scl_aes_256, ecb_F_1_56_high);
    RUN_TEST_CASE(scl_aes_256, cbc_F_2_56);
    RUN_TEST_CASE(scl_aes_256, cbc_F_2_56_high);
}

#endif
