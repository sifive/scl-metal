/**
 * @file test_scl_hmac_runner.c
 * @brief test runner for test_scl_hmac.c tests
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(scl_hmac)
{
    /* HMAC sha 224 */
    RUN_TEST_CASE(scl_hmac, sha224_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(scl_hmac, sha224_keysize_equal_blocksize);
    RUN_TEST_CASE(scl_hmac, sha224_keysize_greater_than_blocksize);

    /* HMAC sha 256 */
    RUN_TEST_CASE(scl_hmac, sha256_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(scl_hmac, sha256_keysize_equal_blocksize);
    RUN_TEST_CASE(scl_hmac, sha256_keysize_greater_than_blocksize);

    /* HMAC sha 384 */
    RUN_TEST_CASE(scl_hmac, sha384_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(scl_hmac, sha384_keysize_equal_blocksize);
    RUN_TEST_CASE(scl_hmac, sha384_keysize_greater_than_blocksize);

    /* HMAC sha 512 */
    RUN_TEST_CASE(scl_hmac, sha512_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(scl_hmac, sha512_keysize_equal_blocksize);
    RUN_TEST_CASE(scl_hmac, sha512_keysize_greater_than_blocksize);
}
