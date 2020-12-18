/**
 * @file test_scl_sha_384.c
 * @brief test suite for scl_sha.c on sha 384 algorithm
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

#include <string.h>

#include <backend/api/scl_backend_api.h>
#include <scl/scl_sha.h>

#include <scl/scl_init.h>

#include <backend/api/hash/sha/sha.h>
#include <backend/software/scl_soft.h>

static const metal_scl_t scl = {.hca_base = 0,
                                .hash_func = {
                                    .sha_init = soft_sha_init,
                                    .sha_core = soft_sha_core,
                                    .sha_finish = soft_sha_finish,
                                }};

TEST_GROUP(scl_soft_sha_384);

TEST_SETUP(scl_soft_sha_384) {}

TEST_TEAR_DOWN(scl_soft_sha_384) {}

TEST(scl_soft_sha_384, msg_abc_all_aligned)
{
    int32_t result = 0;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA384_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA384_BYTE_HASHSIZE] = {
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69,
        0x9A, 0xC6, 0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
        0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B,
        0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7};

    result = scl_sha(&scl, SCL_HASH_SHA384, message, sizeof(message), digest,
                     &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(scl_soft_sha_384, msg_2_blocks_all_aligned)
{
    int32_t result = 0;

    static const uint8_t message[] __attribute__((aligned(8))) =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmn"
        "opjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    uint8_t digest[SHA384_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA384_BYTE_HASHSIZE] = {
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7,
        0x82, 0xCD, 0x1B, 0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
        0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A,
        0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39};

    result = scl_sha(&scl, SCL_HASH_SHA384, message, sizeof(message) - 1,
                     digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(scl_soft_sha_384, msg_abc_msg_not_aligned)
{
    int32_t result = 0;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x00,
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA384_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA384_BYTE_HASHSIZE] = {
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69,
        0x9A, 0xC6, 0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
        0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B,
        0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7};

    result = scl_sha(&scl, SCL_HASH_SHA384, &message[1], sizeof(message) - 1,
                     digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(scl_soft_sha_384, msg_2_blocks_msg_not_aligned)
{
    int32_t result = 0;

    static const uint8_t message[] __attribute__((aligned(8))) =
        "aabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklm"
        "nopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    uint8_t digest[SHA384_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA384_BYTE_HASHSIZE] = {
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7,
        0x82, 0xCD, 0x1B, 0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
        0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A,
        0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39};

    result = scl_sha(&scl, SCL_HASH_SHA384, &message[1], sizeof(message) - 2,
                     digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(scl_soft_sha_384, msg_abc_digest_not_aligned)
{
    int32_t result = 0;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA384_BYTE_HASHSIZE + 1] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest) - 1;

    static const uint8_t expected_digest[SHA384_BYTE_HASHSIZE] = {
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69,
        0x9A, 0xC6, 0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
        0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B,
        0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7};

    result = scl_sha(&scl, SCL_HASH_SHA384, message, sizeof(message),
                     &digest[1], &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(
        0 == memcmp(expected_digest, &digest[1], sizeof(expected_digest)));
}

TEST(scl_soft_sha_384, msg_2_blocks_digest_not_aligned)
{
    int32_t result = 0;

    static const uint8_t message[] __attribute__((aligned(8))) =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmn"
        "opjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    uint8_t digest[SHA384_BYTE_HASHSIZE + 1] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest) - 1;

    static const uint8_t expected_digest[SHA384_BYTE_HASHSIZE] = {
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7,
        0x82, 0xCD, 0x1B, 0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
        0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A,
        0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39};

    result = scl_sha(&scl, SCL_HASH_SHA384, message, sizeof(message) - 1,
                     &digest[1], &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(
        0 == memcmp(expected_digest, &digest[1], sizeof(expected_digest)));
}
