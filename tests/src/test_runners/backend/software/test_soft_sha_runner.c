/**
 * @file test_soft_sha_runner.c
 * @brief test runner for test_soft_sha.c tests
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

// SHA 224
TEST_GROUP_RUNNER(soft_sha_224)
{
    RUN_TEST_CASE(soft_sha_224, msg_abc_all_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_2_blocks_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_1024_bytes_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_1024_bytes_not_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_96B_digest_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_2_block_and_half_digest_aligned);
    RUN_TEST_CASE(soft_sha_224, msg_and_hash_twice);
    RUN_TEST_CASE(soft_sha_224, msg_1_block_in_3_pieces_digest_aligned);
}

// SHA 256
TEST_GROUP_RUNNER(soft_sha_256)
{
    RUN_TEST_CASE(soft_sha_256, msg_abc_all_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_2_blocks_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_1024_bytes_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_1024_bytes_not_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_96B_digest_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_2_block_and_half_digest_aligned);
    RUN_TEST_CASE(soft_sha_256, msg_and_hash_twice);
    RUN_TEST_CASE(soft_sha_256, msg_1_block_in_3_pieces_digest_aligned);
}

// SHA 384
TEST_GROUP_RUNNER(soft_sha_384)
{
    RUN_TEST_CASE(soft_sha_384, msg_abc_all_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_2_blocks_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_1024_bytes_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_1024_bytes_not_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_192B_digest_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_2_block_and_half_digest_aligned);
    RUN_TEST_CASE(soft_sha_384, msg_and_hash_twice);
    RUN_TEST_CASE(soft_sha_384, msg_1_block_in_3_pieces_digest_aligned);
}

// SHA 512
TEST_GROUP_RUNNER(soft_sha_512)
{
    RUN_TEST_CASE(soft_sha_512, msg_abc_all_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_2_blocks_all_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_abc_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_2_blocks_msg_not_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_abc_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_2_blocks_digest_not_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_1024_bytes_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_1024_bytes_not_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_192B_digest_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_2_block_and_half_digest_aligned);
    RUN_TEST_CASE(soft_sha_512, msg_and_hash_twice);
    RUN_TEST_CASE(soft_sha_512, msg_1_block_in_3_pieces_digest_aligned);
}
