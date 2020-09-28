/**
 * @file test_hca_sha_224.c
 * @brief test suite for hca_sha.c on sha 224 algorithm
 * @note These tests use HCA (Hardware Cryptographic Accelerator)
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity.h"
#include "unity_fixture.h"

#include <string.h>

#include <api/hardware/scl_hca.h>
#include <api/hash/sha.h>
#include <api/scl_api.h>

#include <metal/machine/platform.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)

static const metal_scl_t scl = {.hca_base = METAL_SIFIVE_HCA_0_BASE_ADDRESS,
                                .hash_func = {
                                    .sha_init = hca_sha_init,
                                    .sha_core = hca_sha_core,
                                    .sha_finish = hca_sha_finish,
                                }};

TEST_GROUP(hca_sha_224);

TEST_SETUP(hca_sha_224) {}

TEST_TEAR_DOWN(hca_sha_224) {}

TEST(hca_sha_224, msg_abc_all_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA224_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22, 0x86, 0x42,
        0xA4, 0x77, 0xBD, 0xA2, 0x55, 0xB3, 0x2A, 0xAD, 0xBC, 0xE4,
        0xBD, 0xA0, 0xB3, 0xF7, 0xE3, 0x6C, 0x9D, 0xA7};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(hca_sha_224, msg_2_blocks_all_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    uint8_t digest[SHA224_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76, 0xCC, 0x5D, 0xBA,
        0x5D, 0xA1, 0xFD, 0x89, 0x01, 0x50, 0xB0, 0xC6, 0x45, 0x5C,
        0xB4, 0xF5, 0x8B, 0x19, 0x52, 0x52, 0x25, 0x25};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, message, sizeof(message) - 1);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(hca_sha_224, msg_abc_msg_not_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x00,
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA224_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22, 0x86, 0x42,
        0xA4, 0x77, 0xBD, 0xA2, 0x55, 0xB3, 0x2A, 0xAD, 0xBC, 0xE4,
        0xBD, 0xA0, 0xB3, 0xF7, 0xE3, 0x6C, 0x9D, 0xA7};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, &message[1], sizeof(message) - 1);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(hca_sha_224, msg_2_blocks_msg_not_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) =
        "aabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    uint8_t digest[SHA224_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76, 0xCC, 0x5D, 0xBA,
        0x5D, 0xA1, 0xFD, 0x89, 0x01, 0x50, 0xB0, 0xC6, 0x45, 0x5C,
        0xB4, 0xF5, 0x8B, 0x19, 0x52, 0x52, 0x25, 0x25};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, &message[1], sizeof(message) - 2);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(hca_sha_224, msg_abc_digest_not_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA224_BYTE_HASHSIZE + 1] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest) - 1;

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22, 0x86, 0x42,
        0xA4, 0x77, 0xBD, 0xA2, 0x55, 0xB3, 0x2A, 0xAD, 0xBC, 0xE4,
        0xBD, 0xA0, 0xB3, 0xF7, 0xE3, 0x6C, 0x9D, 0xA7};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, &digest[1], &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(
        0 == memcmp(expected_digest, &digest[1], sizeof(expected_digest)));
}

TEST(hca_sha_224, msg_2_blocks_digest_not_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    uint8_t digest[SHA224_BYTE_HASHSIZE + 1] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest) - 1;

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x75, 0x38, 0x8B, 0x16, 0x51, 0x27, 0x76, 0xCC, 0x5D, 0xBA,
        0x5D, 0xA1, 0xFD, 0x89, 0x01, 0x50, 0xB0, 0xC6, 0x45, 0x5C,
        0xB4, 0xF5, 0x8B, 0x19, 0x52, 0x52, 0x25, 0x25};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, message, sizeof(message) - 1);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, &digest[1], &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(
        0 == memcmp(expected_digest, &digest[1], sizeof(expected_digest)));
}

TEST(hca_sha_224, msg_1024_bytes_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x10, 0x94, 0xA3, 0x93, 0x1D, 0x00, 0xFC, 0x89, 0x5F, 0xA2, 0x57, 0x6F,
        0xD6, 0x37, 0xBF, 0x1B, 0xC8, 0xF7, 0xBB, 0x1D, 0xBB, 0x7C, 0xDF, 0xEF,
        0x41, 0x41, 0x7A, 0x02, 0xA2, 0x39, 0xD4, 0xBE, 0xC4, 0x0F, 0xCC, 0x76,
        0x8E, 0xA8, 0x51, 0x83, 0x0C, 0xDF, 0x73, 0x3C, 0x19, 0x38, 0xF2, 0xB1,
        0xB1, 0x73, 0x20, 0x40, 0xBA, 0xA3, 0x9A, 0x8D, 0xAB, 0xA0, 0xCA, 0xD3,
        0xF2, 0xE8, 0xC3, 0x14, 0xCB, 0xAC, 0x66, 0xBF, 0xD0, 0x46, 0x1B, 0xAC,
        0xBB, 0xD0, 0xF5, 0x36, 0xCD, 0x75, 0xE8, 0x9E, 0x56, 0x2E, 0x2F, 0x3A,
        0x1E, 0xAB, 0xF5, 0x90, 0x35, 0xC7, 0xEE, 0x05, 0xEC, 0xC8, 0x2E, 0x7E,
        0x41, 0x06, 0xFC, 0x05, 0x31, 0xCC, 0x59, 0x36, 0x98, 0xA8, 0x84, 0xC0,
        0x76, 0x9D, 0x85, 0x09, 0xCC, 0xD5, 0x5B, 0xE1, 0x3B, 0xA9, 0xB9, 0x5C,
        0x97, 0xAF, 0x1A, 0xB8, 0x99, 0x71, 0xAF, 0x80, 0xF2, 0x77, 0x8B, 0xF7,
        0x1E, 0xA8, 0x66, 0x83, 0x38, 0xF7, 0x03, 0xE1, 0x9C, 0x15, 0xB5, 0x69,
        0xA7, 0x8B, 0x6E, 0x45, 0xFA, 0x05, 0xB8, 0x00, 0x8A, 0x0B, 0x39, 0x14,
        0x6C, 0xA8, 0xF2, 0xCD, 0x43, 0x31, 0x05, 0x01, 0x4B, 0x7B, 0x75, 0x6F,
        0x2F, 0xF6, 0x8E, 0x70, 0x97, 0x8F, 0x11, 0x0B, 0xAF, 0xAE, 0x28, 0x74,
        0x30, 0x85, 0xB8, 0x04, 0x34, 0x6F, 0xB9, 0xC1, 0x4D, 0xA7, 0x97, 0x98,
        0xEC, 0xC6, 0xC2, 0x52, 0x7E, 0xE2, 0x38, 0x6E, 0x21, 0x6B, 0x3F, 0xBA,
        0x0D, 0x99, 0x54, 0xDE, 0x1F, 0xE7, 0x98, 0xED, 0x24, 0xD2, 0xA7, 0xF9,
        0x44, 0xF0, 0x5C, 0xD7, 0xEF, 0x30, 0x24, 0x9C, 0x02, 0x8A, 0xEA, 0xF9,
        0x35, 0x2D, 0x2A, 0x2B, 0x2E, 0x14, 0x84, 0x6C, 0x9A, 0x30, 0x9B, 0xFF,
        0xAA, 0x3E, 0xC1, 0xB0, 0x39, 0x56, 0x05, 0x59, 0x19, 0x23, 0xAD, 0x60,
        0xF6, 0x89, 0x9B, 0xAF, 0x61, 0xD5, 0x5B, 0xE1, 0xE7, 0x32, 0xDD, 0x24,
        0x25, 0x72, 0x4C, 0xF3, 0xF4, 0xEF, 0xF6, 0x57, 0xC1, 0xF2, 0xE5, 0xF8,
        0x34, 0xCA, 0x22, 0xE0, 0x53, 0x5D, 0x40, 0x50, 0x6A, 0xEA, 0x83, 0xE4,
        0x4E, 0xF0, 0x8E, 0x64, 0x5E, 0x04, 0xAF, 0x53, 0x4E, 0x9D, 0x2A, 0xCD,
        0xE3, 0x3B, 0x1F, 0x92, 0x51, 0xF7, 0x4F, 0x90, 0xA9, 0x33, 0xF7, 0x72,
        0x5C, 0xA5, 0x5B, 0x0B, 0x7B, 0x95, 0xC0, 0x90, 0xA8, 0xD1, 0x6C, 0x3A,
        0x72, 0x91, 0xA8, 0x37, 0xB2, 0x95, 0x27, 0xB0, 0xDD, 0x77, 0xE0, 0x9F,
        0x78, 0xC5, 0xBF, 0x8F, 0x59, 0x5B, 0x90, 0xBA, 0xAC, 0x05, 0x8F, 0xC8,
        0x51, 0xF1, 0xFF, 0xEC, 0x71, 0x66, 0x93, 0xAE, 0x5D, 0x34, 0xDE, 0x57,
        0x64, 0xB8, 0xBF, 0x10, 0x8D, 0xF5, 0x67, 0x34, 0xA4, 0xF1, 0xD9, 0x7D,
        0xAB, 0x84, 0x31, 0xB5, 0x15, 0x6C, 0xD6, 0xFD, 0xDA, 0xD7, 0xFC, 0xA1,
        0xE6, 0x96, 0xC6, 0xFB, 0x99, 0x35, 0x41, 0xA4, 0x01, 0x17, 0x45, 0xB2,
        0x16, 0x57, 0x5F, 0xDA, 0x04, 0xED, 0xC1, 0x88, 0xA7, 0xBE, 0x4A, 0x55,
        0x6F, 0x21, 0x04, 0xD2, 0xCC, 0xE8, 0x73, 0xF0, 0x2E, 0xE6, 0x1A, 0xA8,
        0x7F, 0xA6, 0x91, 0x04, 0xC5, 0x3D, 0x31, 0xE2, 0xDB, 0x5A, 0x6B, 0xE6,
        0xF9, 0x8E, 0xB1, 0x02, 0xB3, 0x1D, 0xD2, 0xA5, 0x37, 0x54, 0x1D, 0x97,
        0x3F, 0xDF, 0xBB, 0xCB, 0xBA, 0x1F, 0x8B, 0x69, 0x37, 0x0B, 0x10, 0xEB,
        0x36, 0xEB, 0x79, 0x44, 0xBA, 0x29, 0x46, 0xF7, 0xD6, 0xB5, 0x7E, 0xFA,
        0x31, 0x4B, 0xFE, 0x8F, 0x69, 0x93, 0x7D, 0x4B, 0x4D, 0xBF, 0xD9, 0x6D,
        0x39, 0x46, 0xE9, 0xA3, 0xC7, 0xF6, 0xB6, 0x2D, 0x52, 0xAD, 0x06, 0x14,
        0xDE, 0xF0, 0xB1, 0xA1, 0xAB, 0x47, 0xD7, 0x05, 0x06, 0xB9, 0xB6, 0xFF,
        0x54, 0x02, 0xEB, 0xA7, 0x26, 0xDC, 0x2D, 0xDE, 0x68, 0x0E, 0x72, 0x62,
        0x4A, 0xF1, 0xE6, 0xAE, 0x41, 0x06, 0xD9, 0xCF, 0x70, 0xF9, 0x34, 0xE2,
        0x4E, 0x54, 0xC6, 0x76, 0xE6, 0x85, 0xDE, 0x06, 0xBD, 0x44, 0x3B, 0x26,
        0xAE, 0x56, 0x96, 0x89, 0x6B, 0xE5, 0x52, 0x98, 0x71, 0x45, 0x67, 0x26,
        0x8E, 0xD1, 0x2D, 0x4E, 0x05, 0x80, 0x32, 0x23, 0x50, 0x9F, 0x36, 0xFA,
        0x0F, 0xD9, 0x9E, 0x54, 0xCB, 0xDF, 0xDD, 0x96, 0x82, 0xFE, 0x9D, 0x6B,
        0xB5, 0x57, 0x92, 0x62, 0xB8, 0x8C, 0xAB, 0xD5, 0x7E, 0x72, 0xF6, 0xAD,
        0x7F, 0xD1, 0x70, 0x70, 0x9D, 0x33, 0xF7, 0xF7, 0x69, 0xAC, 0xEC, 0x6A,
        0x1C, 0x20, 0x0F, 0x51, 0x0A, 0x73, 0x9A, 0xD7, 0x20, 0x95, 0x68, 0xE4,
        0x5A, 0xAE, 0xA2, 0xFA, 0x86, 0x0D, 0xFE, 0x7F, 0x8C, 0xD0, 0x87, 0xEC,
        0xC5, 0x0C, 0xFB, 0xBC, 0x89, 0xCF, 0x13, 0x95, 0x9E, 0xD3, 0x25, 0x93,
        0x45, 0x95, 0x1F, 0x29, 0xD4, 0x58, 0x4C, 0xF0, 0x58, 0x3E, 0x53, 0xAE,
        0x49, 0x1B, 0xDA, 0x9B, 0xA7, 0x12, 0x76, 0xBD, 0xC9, 0xA1, 0xE3, 0xBA,
        0x7C, 0x89, 0x4D, 0x43, 0xE0, 0x77, 0xCC, 0xE2, 0xA3, 0x0E, 0x50, 0xB9,
        0xF6, 0x8E, 0x85, 0x66, 0xB0, 0x77, 0x9C, 0x3B, 0x2B, 0x5C, 0xAF, 0xF9,
        0xEB, 0xF7, 0x7E, 0xAB, 0x4A, 0xDB, 0x5F, 0x8E, 0x19, 0xD8, 0x75, 0x5F,
        0xFE, 0x07, 0x95, 0xCE, 0xBB, 0x11, 0x4D, 0x41, 0x78, 0x09, 0x90, 0x62,
        0x7C, 0x01, 0x27, 0x0B, 0x7A, 0xD9, 0xD8, 0x5D, 0x72, 0x5C, 0xA1, 0x35,
        0x79, 0x03, 0x9C, 0x68, 0xF5, 0x97, 0xFD, 0x0C, 0xFF, 0xB4, 0xBA, 0x1D,
        0x8F, 0x03, 0x0B, 0xEA, 0xAF, 0xF0, 0x75, 0x9F, 0xA8, 0x50, 0xD9, 0x40,
        0xAB, 0x93, 0xC0, 0xF1, 0xE2, 0x1D, 0x7B, 0xAA, 0xE7, 0x88, 0x36, 0x89,
        0x1B, 0xC1, 0x87, 0x6D, 0x32, 0xE7, 0x03, 0x87, 0x78, 0xA6, 0x96, 0xB0,
        0xD9, 0xA4, 0xC3, 0x4A, 0x99, 0xA3, 0x9A, 0x7A, 0xCC, 0xE6, 0xFD, 0xE8,
        0xB7, 0x01, 0x08, 0xB6, 0x0B, 0x06, 0x84, 0x62, 0x30, 0x4D, 0x40, 0xAC,
        0x5B, 0x88, 0xAB, 0x7B, 0x4C, 0x93, 0xB3, 0x5A, 0x92, 0x34, 0x76, 0x8B,
        0x3E, 0x29, 0xEF, 0x27, 0x42, 0xBC, 0x38, 0x72, 0x68, 0x58, 0xBF, 0x6F,
        0xE1, 0x25, 0x4A, 0x14, 0xB6, 0x44, 0xD1, 0x55, 0x4B, 0x5D, 0x7C, 0x73,
        0xD7, 0xCF, 0x54, 0x17, 0xA3, 0x06, 0xAF, 0xF7, 0x11, 0xD5, 0xA4, 0xA9,
        0xFC, 0x21, 0xC0, 0x57, 0x2B, 0xAD, 0xFD, 0x9B, 0x07, 0xFF, 0x65, 0x3C,
        0x5E, 0x55, 0x3C, 0x60, 0xBC, 0xE9, 0x0F, 0x17, 0xC5, 0xC8, 0x01, 0x08,
        0xCD, 0x6C, 0x16, 0x1F, 0x6F, 0xF3, 0xC3, 0x98, 0xF3, 0xC3, 0x43, 0x09,
        0x08, 0x00, 0x41, 0x54, 0x86, 0x18, 0xBE, 0xD1, 0x1D, 0xF5, 0x75, 0x36,
        0x3B, 0x46, 0xCD, 0x8E, 0x89, 0x06, 0xED, 0x2E, 0x58, 0xCB, 0x32, 0xD3,
        0x1A, 0xF5, 0xC8, 0x01, 0x4E, 0x66, 0xF3, 0x6D, 0x5A, 0x67, 0xE9, 0x59,
        0x3B, 0x5B, 0x54, 0x1C, 0x14, 0x5C, 0x96, 0xE7, 0x03, 0x6C, 0xA4, 0x5C,
        0x0A, 0x01, 0x40, 0xBC, 0x50, 0xF4, 0xD9, 0x97, 0xEC, 0x00, 0xA2, 0x3F,
        0x72, 0x8B, 0xF8, 0x36, 0xBA, 0x75, 0x7B, 0x8D, 0xEE, 0x98, 0xA1, 0x2A,
        0xBE, 0x39, 0x83, 0x17, 0xC8, 0x29, 0xCB, 0x2F, 0x58, 0x81, 0x23, 0xAB,
        0x49, 0x70, 0x4F, 0xDA, 0x3A, 0xD9, 0xE2, 0xBD, 0x76, 0x67, 0xC3, 0x11,
        0x5B, 0x30, 0x97, 0x33, 0x74, 0x07, 0xC7, 0xDE, 0xCC, 0x36, 0x60, 0xA6,
        0xE8, 0x31, 0x43, 0xA6, 0x62, 0xF4, 0x2A, 0x23, 0xD7, 0x9B, 0xBC, 0xB3,
        0x69, 0x7F, 0x0C, 0x20, 0xC4, 0xD9, 0x77, 0x26, 0xC5, 0x51, 0x22, 0xE1,
        0xDF, 0x6E, 0x8E, 0x29, 0xFF, 0xB5, 0x9A, 0x35, 0xD6, 0x5B, 0x4D, 0x59,
        0x12, 0x2A, 0xC5, 0x5E};

    uint8_t digest[SHA224_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x80, 0x41, 0x36, 0x54, 0xEC, 0xE9, 0xEB, 0x7B, 0xE0, 0x50,
        0xC5, 0x25, 0xC0, 0x5A, 0x17, 0x65, 0x90, 0x9F, 0x2F, 0xE9,
        0xCC, 0xF6, 0xEB, 0xD3, 0xAC, 0xC3, 0x8C, 0x1F};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

TEST(hca_sha_224, msg_1024_bytes_not_aligned)
{
    int32_t result = 0;
    sha_ctx_t ctx;

    static const uint8_t message[] __attribute__((aligned(8))) = {
        0x00, 0x10, 0x94, 0xA3, 0x93, 0x1D, 0x00, 0xFC, 0x89, 0x5F, 0xA2, 0x57,
        0x6F, 0xD6, 0x37, 0xBF, 0x1B, 0xC8, 0xF7, 0xBB, 0x1D, 0xBB, 0x7C, 0xDF,
        0xEF, 0x41, 0x41, 0x7A, 0x02, 0xA2, 0x39, 0xD4, 0xBE, 0xC4, 0x0F, 0xCC,
        0x76, 0x8E, 0xA8, 0x51, 0x83, 0x0C, 0xDF, 0x73, 0x3C, 0x19, 0x38, 0xF2,
        0xB1, 0xB1, 0x73, 0x20, 0x40, 0xBA, 0xA3, 0x9A, 0x8D, 0xAB, 0xA0, 0xCA,
        0xD3, 0xF2, 0xE8, 0xC3, 0x14, 0xCB, 0xAC, 0x66, 0xBF, 0xD0, 0x46, 0x1B,
        0xAC, 0xBB, 0xD0, 0xF5, 0x36, 0xCD, 0x75, 0xE8, 0x9E, 0x56, 0x2E, 0x2F,
        0x3A, 0x1E, 0xAB, 0xF5, 0x90, 0x35, 0xC7, 0xEE, 0x05, 0xEC, 0xC8, 0x2E,
        0x7E, 0x41, 0x06, 0xFC, 0x05, 0x31, 0xCC, 0x59, 0x36, 0x98, 0xA8, 0x84,
        0xC0, 0x76, 0x9D, 0x85, 0x09, 0xCC, 0xD5, 0x5B, 0xE1, 0x3B, 0xA9, 0xB9,
        0x5C, 0x97, 0xAF, 0x1A, 0xB8, 0x99, 0x71, 0xAF, 0x80, 0xF2, 0x77, 0x8B,
        0xF7, 0x1E, 0xA8, 0x66, 0x83, 0x38, 0xF7, 0x03, 0xE1, 0x9C, 0x15, 0xB5,
        0x69, 0xA7, 0x8B, 0x6E, 0x45, 0xFA, 0x05, 0xB8, 0x00, 0x8A, 0x0B, 0x39,
        0x14, 0x6C, 0xA8, 0xF2, 0xCD, 0x43, 0x31, 0x05, 0x01, 0x4B, 0x7B, 0x75,
        0x6F, 0x2F, 0xF6, 0x8E, 0x70, 0x97, 0x8F, 0x11, 0x0B, 0xAF, 0xAE, 0x28,
        0x74, 0x30, 0x85, 0xB8, 0x04, 0x34, 0x6F, 0xB9, 0xC1, 0x4D, 0xA7, 0x97,
        0x98, 0xEC, 0xC6, 0xC2, 0x52, 0x7E, 0xE2, 0x38, 0x6E, 0x21, 0x6B, 0x3F,
        0xBA, 0x0D, 0x99, 0x54, 0xDE, 0x1F, 0xE7, 0x98, 0xED, 0x24, 0xD2, 0xA7,
        0xF9, 0x44, 0xF0, 0x5C, 0xD7, 0xEF, 0x30, 0x24, 0x9C, 0x02, 0x8A, 0xEA,
        0xF9, 0x35, 0x2D, 0x2A, 0x2B, 0x2E, 0x14, 0x84, 0x6C, 0x9A, 0x30, 0x9B,
        0xFF, 0xAA, 0x3E, 0xC1, 0xB0, 0x39, 0x56, 0x05, 0x59, 0x19, 0x23, 0xAD,
        0x60, 0xF6, 0x89, 0x9B, 0xAF, 0x61, 0xD5, 0x5B, 0xE1, 0xE7, 0x32, 0xDD,
        0x24, 0x25, 0x72, 0x4C, 0xF3, 0xF4, 0xEF, 0xF6, 0x57, 0xC1, 0xF2, 0xE5,
        0xF8, 0x34, 0xCA, 0x22, 0xE0, 0x53, 0x5D, 0x40, 0x50, 0x6A, 0xEA, 0x83,
        0xE4, 0x4E, 0xF0, 0x8E, 0x64, 0x5E, 0x04, 0xAF, 0x53, 0x4E, 0x9D, 0x2A,
        0xCD, 0xE3, 0x3B, 0x1F, 0x92, 0x51, 0xF7, 0x4F, 0x90, 0xA9, 0x33, 0xF7,
        0x72, 0x5C, 0xA5, 0x5B, 0x0B, 0x7B, 0x95, 0xC0, 0x90, 0xA8, 0xD1, 0x6C,
        0x3A, 0x72, 0x91, 0xA8, 0x37, 0xB2, 0x95, 0x27, 0xB0, 0xDD, 0x77, 0xE0,
        0x9F, 0x78, 0xC5, 0xBF, 0x8F, 0x59, 0x5B, 0x90, 0xBA, 0xAC, 0x05, 0x8F,
        0xC8, 0x51, 0xF1, 0xFF, 0xEC, 0x71, 0x66, 0x93, 0xAE, 0x5D, 0x34, 0xDE,
        0x57, 0x64, 0xB8, 0xBF, 0x10, 0x8D, 0xF5, 0x67, 0x34, 0xA4, 0xF1, 0xD9,
        0x7D, 0xAB, 0x84, 0x31, 0xB5, 0x15, 0x6C, 0xD6, 0xFD, 0xDA, 0xD7, 0xFC,
        0xA1, 0xE6, 0x96, 0xC6, 0xFB, 0x99, 0x35, 0x41, 0xA4, 0x01, 0x17, 0x45,
        0xB2, 0x16, 0x57, 0x5F, 0xDA, 0x04, 0xED, 0xC1, 0x88, 0xA7, 0xBE, 0x4A,
        0x55, 0x6F, 0x21, 0x04, 0xD2, 0xCC, 0xE8, 0x73, 0xF0, 0x2E, 0xE6, 0x1A,
        0xA8, 0x7F, 0xA6, 0x91, 0x04, 0xC5, 0x3D, 0x31, 0xE2, 0xDB, 0x5A, 0x6B,
        0xE6, 0xF9, 0x8E, 0xB1, 0x02, 0xB3, 0x1D, 0xD2, 0xA5, 0x37, 0x54, 0x1D,
        0x97, 0x3F, 0xDF, 0xBB, 0xCB, 0xBA, 0x1F, 0x8B, 0x69, 0x37, 0x0B, 0x10,
        0xEB, 0x36, 0xEB, 0x79, 0x44, 0xBA, 0x29, 0x46, 0xF7, 0xD6, 0xB5, 0x7E,
        0xFA, 0x31, 0x4B, 0xFE, 0x8F, 0x69, 0x93, 0x7D, 0x4B, 0x4D, 0xBF, 0xD9,
        0x6D, 0x39, 0x46, 0xE9, 0xA3, 0xC7, 0xF6, 0xB6, 0x2D, 0x52, 0xAD, 0x06,
        0x14, 0xDE, 0xF0, 0xB1, 0xA1, 0xAB, 0x47, 0xD7, 0x05, 0x06, 0xB9, 0xB6,
        0xFF, 0x54, 0x02, 0xEB, 0xA7, 0x26, 0xDC, 0x2D, 0xDE, 0x68, 0x0E, 0x72,
        0x62, 0x4A, 0xF1, 0xE6, 0xAE, 0x41, 0x06, 0xD9, 0xCF, 0x70, 0xF9, 0x34,
        0xE2, 0x4E, 0x54, 0xC6, 0x76, 0xE6, 0x85, 0xDE, 0x06, 0xBD, 0x44, 0x3B,
        0x26, 0xAE, 0x56, 0x96, 0x89, 0x6B, 0xE5, 0x52, 0x98, 0x71, 0x45, 0x67,
        0x26, 0x8E, 0xD1, 0x2D, 0x4E, 0x05, 0x80, 0x32, 0x23, 0x50, 0x9F, 0x36,
        0xFA, 0x0F, 0xD9, 0x9E, 0x54, 0xCB, 0xDF, 0xDD, 0x96, 0x82, 0xFE, 0x9D,
        0x6B, 0xB5, 0x57, 0x92, 0x62, 0xB8, 0x8C, 0xAB, 0xD5, 0x7E, 0x72, 0xF6,
        0xAD, 0x7F, 0xD1, 0x70, 0x70, 0x9D, 0x33, 0xF7, 0xF7, 0x69, 0xAC, 0xEC,
        0x6A, 0x1C, 0x20, 0x0F, 0x51, 0x0A, 0x73, 0x9A, 0xD7, 0x20, 0x95, 0x68,
        0xE4, 0x5A, 0xAE, 0xA2, 0xFA, 0x86, 0x0D, 0xFE, 0x7F, 0x8C, 0xD0, 0x87,
        0xEC, 0xC5, 0x0C, 0xFB, 0xBC, 0x89, 0xCF, 0x13, 0x95, 0x9E, 0xD3, 0x25,
        0x93, 0x45, 0x95, 0x1F, 0x29, 0xD4, 0x58, 0x4C, 0xF0, 0x58, 0x3E, 0x53,
        0xAE, 0x49, 0x1B, 0xDA, 0x9B, 0xA7, 0x12, 0x76, 0xBD, 0xC9, 0xA1, 0xE3,
        0xBA, 0x7C, 0x89, 0x4D, 0x43, 0xE0, 0x77, 0xCC, 0xE2, 0xA3, 0x0E, 0x50,
        0xB9, 0xF6, 0x8E, 0x85, 0x66, 0xB0, 0x77, 0x9C, 0x3B, 0x2B, 0x5C, 0xAF,
        0xF9, 0xEB, 0xF7, 0x7E, 0xAB, 0x4A, 0xDB, 0x5F, 0x8E, 0x19, 0xD8, 0x75,
        0x5F, 0xFE, 0x07, 0x95, 0xCE, 0xBB, 0x11, 0x4D, 0x41, 0x78, 0x09, 0x90,
        0x62, 0x7C, 0x01, 0x27, 0x0B, 0x7A, 0xD9, 0xD8, 0x5D, 0x72, 0x5C, 0xA1,
        0x35, 0x79, 0x03, 0x9C, 0x68, 0xF5, 0x97, 0xFD, 0x0C, 0xFF, 0xB4, 0xBA,
        0x1D, 0x8F, 0x03, 0x0B, 0xEA, 0xAF, 0xF0, 0x75, 0x9F, 0xA8, 0x50, 0xD9,
        0x40, 0xAB, 0x93, 0xC0, 0xF1, 0xE2, 0x1D, 0x7B, 0xAA, 0xE7, 0x88, 0x36,
        0x89, 0x1B, 0xC1, 0x87, 0x6D, 0x32, 0xE7, 0x03, 0x87, 0x78, 0xA6, 0x96,
        0xB0, 0xD9, 0xA4, 0xC3, 0x4A, 0x99, 0xA3, 0x9A, 0x7A, 0xCC, 0xE6, 0xFD,
        0xE8, 0xB7, 0x01, 0x08, 0xB6, 0x0B, 0x06, 0x84, 0x62, 0x30, 0x4D, 0x40,
        0xAC, 0x5B, 0x88, 0xAB, 0x7B, 0x4C, 0x93, 0xB3, 0x5A, 0x92, 0x34, 0x76,
        0x8B, 0x3E, 0x29, 0xEF, 0x27, 0x42, 0xBC, 0x38, 0x72, 0x68, 0x58, 0xBF,
        0x6F, 0xE1, 0x25, 0x4A, 0x14, 0xB6, 0x44, 0xD1, 0x55, 0x4B, 0x5D, 0x7C,
        0x73, 0xD7, 0xCF, 0x54, 0x17, 0xA3, 0x06, 0xAF, 0xF7, 0x11, 0xD5, 0xA4,
        0xA9, 0xFC, 0x21, 0xC0, 0x57, 0x2B, 0xAD, 0xFD, 0x9B, 0x07, 0xFF, 0x65,
        0x3C, 0x5E, 0x55, 0x3C, 0x60, 0xBC, 0xE9, 0x0F, 0x17, 0xC5, 0xC8, 0x01,
        0x08, 0xCD, 0x6C, 0x16, 0x1F, 0x6F, 0xF3, 0xC3, 0x98, 0xF3, 0xC3, 0x43,
        0x09, 0x08, 0x00, 0x41, 0x54, 0x86, 0x18, 0xBE, 0xD1, 0x1D, 0xF5, 0x75,
        0x36, 0x3B, 0x46, 0xCD, 0x8E, 0x89, 0x06, 0xED, 0x2E, 0x58, 0xCB, 0x32,
        0xD3, 0x1A, 0xF5, 0xC8, 0x01, 0x4E, 0x66, 0xF3, 0x6D, 0x5A, 0x67, 0xE9,
        0x59, 0x3B, 0x5B, 0x54, 0x1C, 0x14, 0x5C, 0x96, 0xE7, 0x03, 0x6C, 0xA4,
        0x5C, 0x0A, 0x01, 0x40, 0xBC, 0x50, 0xF4, 0xD9, 0x97, 0xEC, 0x00, 0xA2,
        0x3F, 0x72, 0x8B, 0xF8, 0x36, 0xBA, 0x75, 0x7B, 0x8D, 0xEE, 0x98, 0xA1,
        0x2A, 0xBE, 0x39, 0x83, 0x17, 0xC8, 0x29, 0xCB, 0x2F, 0x58, 0x81, 0x23,
        0xAB, 0x49, 0x70, 0x4F, 0xDA, 0x3A, 0xD9, 0xE2, 0xBD, 0x76, 0x67, 0xC3,
        0x11, 0x5B, 0x30, 0x97, 0x33, 0x74, 0x07, 0xC7, 0xDE, 0xCC, 0x36, 0x60,
        0xA6, 0xE8, 0x31, 0x43, 0xA6, 0x62, 0xF4, 0x2A, 0x23, 0xD7, 0x9B, 0xBC,
        0xB3, 0x69, 0x7F, 0x0C, 0x20, 0xC4, 0xD9, 0x77, 0x26, 0xC5, 0x51, 0x22,
        0xE1, 0xDF, 0x6E, 0x8E, 0x29, 0xFF, 0xB5, 0x9A, 0x35, 0xD6, 0x5B, 0x4D,
        0x59, 0x12, 0x2A, 0xC5, 0x5E};

    uint8_t digest[SHA224_BYTE_HASHSIZE] __attribute__((aligned(8)));
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA224_BYTE_HASHSIZE] = {
        0x80, 0x41, 0x36, 0x54, 0xEC, 0xE9, 0xEB, 0x7B, 0xE0, 0x50,
        0xC5, 0x25, 0xC0, 0x5A, 0x17, 0x65, 0x90, 0x9F, 0x2F, 0xE9,
        0xCC, 0xF6, 0xEB, 0xD3, 0xAC, 0xC3, 0x8C, 0x1F};

    result = hca_sha_init(&scl, &ctx, SCL_HASH_SHA224, SCL_BIG_ENDIAN_MODE);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_core(&scl, &ctx, &message[1], sizeof(message) - 1);
    TEST_ASSERT_TRUE(0 == result);

    result = hca_sha_finish(&scl, &ctx, digest, &digest_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == digest_len);
    TEST_ASSERT_TRUE(0 ==
                     memcmp(expected_digest, digest, sizeof(expected_digest)));
}

#endif
