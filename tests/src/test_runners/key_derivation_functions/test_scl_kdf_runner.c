/**
 * @file test_scl_kdf_runner.c
 * @brief test runner for test_scl_kdf.c tests
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(scl_kdf)
{
    /* HMAC sha 224 */
    RUN_TEST_CASE(scl_kdf, x963kdf_sha224_output_19B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha224_output_32B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha224_output_97B);

    /* HMAC sha 256 */
    RUN_TEST_CASE(scl_kdf, x963kdf_sha256_output_19B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha256_output_32B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha256_output_97B);

    /* HMAC sha 384 */
    RUN_TEST_CASE(scl_kdf, x963kdf_sha384_output_19B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha384_output_32B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha384_output_97B);

    /* HMAC sha 512 */
    RUN_TEST_CASE(scl_kdf, x963kdf_sha512_output_19B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha512_output_32B);
    RUN_TEST_CASE(scl_kdf, x963kdf_sha512_output_97B);
}
