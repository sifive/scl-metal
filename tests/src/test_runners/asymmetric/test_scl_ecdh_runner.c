/**
 * @file test_scl_ecdh_runner.c
 * @brief test runner for test_scl_ecdh.c tests
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(scl_ecdh)
{
    /* SECP256r1 */
    RUN_TEST_CASE(scl_ecdh, secp_p256r1_curve_success);
    RUN_TEST_CASE(scl_ecdh, secp_p256r1_curve_not_on_curve);

    /* SECP384r1 */
    RUN_TEST_CASE(scl_ecdh, secp_p384r1_curve_success);
    RUN_TEST_CASE(scl_ecdh, secp_p384r1_curve_not_on_curve);

    /* SECP521r1 */
    RUN_TEST_CASE(scl_ecdh, secp_p521r1_curve_success);
    RUN_TEST_CASE(scl_ecdh, secp_p521r1_curve_not_on_curve);
}
