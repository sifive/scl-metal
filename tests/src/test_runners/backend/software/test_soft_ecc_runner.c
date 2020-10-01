/**
 * @file test_soft_ecc_runner.c
 * @brief test runner for test_soft_ecc.c
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(soft_ecc)
{
    RUN_TEST_CASE(soft_ecc, test_p384r1_affine_2_jacobian_2_affine);
    RUN_TEST_CASE(soft_ecc, test_p384r1_double_affine_point_via_jacobian);
    RUN_TEST_CASE(soft_ecc, test_p384r1_add_affine_point_via_jacobian);
    RUN_TEST_CASE(soft_ecc, test_soft_ecc_mult_coz);
    RUN_TEST_CASE(soft_ecc, test_soft_ecc_xycz_addc);
}
