/**
 * @file test_soft_ecc_keygen_runner.c
 * @brief test runner for test_soft_ecc_keygen.c
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(soft_ecc_keygen)
{
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_point_on_curve_secp356r1_point_success);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_point_on_curve_secp384r1_point_success);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_point_on_curve_secp521r1_point_success);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_point_on_curve_secp256r1_point_failure);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_point_on_curve_secp384r1_point_failure);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_point_on_curve_secp521r1_point_failure);

    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_pubkey_generation_secp256r1_success);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_pubkey_generation_secp384r1_success);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_pubkey_generation_secp521r1_success);

    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_keypair_generation_secp256r1_success);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_keypair_generation_secp384r1_success);
    RUN_TEST_CASE(soft_ecc_keygen,
                  soft_ecc_keypair_generation_secp521r1_success);
}
