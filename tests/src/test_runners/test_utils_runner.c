/**
 * @file test_utils_runner.c
 * @brief test runner for test_utils.c tests
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(utils)
{
    RUN_TEST_CASE(utils, memcpy_u64_success);
    RUN_TEST_CASE(utils, memset_u64_success);
}
