/**
 * @file test_scl_ecc_keygen_runner.c
 * @brief test runner for test_scl_ecc_keygen.c
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(scl_ecc_keygen)
{
    RUN_TEST_CASE(scl_ecc_keygen, scl_ecc_keygen_secp256r1_all_in_one);
    RUN_TEST_CASE(scl_ecc_keygen, scl_ecc_keygen_secp384r1_all_in_one);
    RUN_TEST_CASE(scl_ecc_keygen, scl_ecc_keygen_secp521r1_all_in_one);
}
