/**
 * @file test_scl_sha_runner.c
 * @brief test runner for test_scl_sha.c
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

// SHA 224
TEST_GROUP_RUNNER(scl_soft_sha_224)
{
    RUN_TEST_CASE(scl_soft_sha_224, msg_abc_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_224, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_224, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_224, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_224, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_224, msg_2_blocks_digest_not_aligned);
}

// SHA 256
TEST_GROUP_RUNNER(scl_soft_sha_256)
{
    RUN_TEST_CASE(scl_soft_sha_256, msg_abc_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_256, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_256, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_256, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_256, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_256, msg_2_blocks_digest_not_aligned);
}

// SHA 384
TEST_GROUP_RUNNER(scl_soft_sha_384)
{
    RUN_TEST_CASE(scl_soft_sha_384, msg_abc_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_384, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_384, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_384, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_384, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_384, msg_2_blocks_digest_not_aligned);
}

// SHA 512
TEST_GROUP_RUNNER(scl_soft_sha_512)
{
    RUN_TEST_CASE(scl_soft_sha_512, msg_abc_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_512, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(scl_soft_sha_512, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_512, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_512, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(scl_soft_sha_512, msg_2_blocks_digest_not_aligned);
}
