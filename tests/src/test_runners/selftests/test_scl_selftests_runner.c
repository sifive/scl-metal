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

TEST_GROUP_RUNNER(scl_selftests)
{
    RUN_TEST_CASE(scl_selftests, scl_ecdsa_p256r1_sha256_selftest);

    RUN_TEST_CASE(scl_selftests, scl_ecdsa_p384r1_sha384_selftest);

    RUN_TEST_CASE(scl_selftests, scl_ecdsa_p521r1_sha512_selftest);

    RUN_TEST_CASE(scl_selftests, scl_hash_sha256_selftest);

    RUN_TEST_CASE(scl_selftests, scl_hash_sha384_selftest);

    RUN_TEST_CASE(scl_selftests, scl_hash_sha512_selftest);
}
