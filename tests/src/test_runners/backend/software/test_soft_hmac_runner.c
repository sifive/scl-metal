/**
 * @file test_soft_hmac_runner.c
 * @brief test runner for test_soft_hmac.c tests
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(soft_hmac)
{
    /* HMAC sha 224 */
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha224_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha224_keysize_equal_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha224_keysize_greater_than_blocksize);

    /* HMAC sha 256 */
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha256_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha256_keysize_equal_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha256_keysize_greater_than_blocksize);

    /* HMAC sha 384 */
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha384_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha384_keysize_equal_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha384_keysize_greater_than_blocksize);

    /* HMAC sha 512 */
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha512_keysize_shorter_than_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha512_keysize_equal_blocksize);
    RUN_TEST_CASE(soft_hmac, soft_hmac_sha512_keysize_greater_than_blocksize);
}
