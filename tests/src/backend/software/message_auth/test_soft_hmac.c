/**
 * @file test_soft_hmac.c
 * @brief test suite for soft_hmac.c
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

#include <string.h>

#include <backend/api/scl_backend_api.h>
#include <backend/software/hash/sha/soft_sha.h>
#include <backend/software/message_auth/soft_hmac.h>

static const metal_scl_t scl = {.hca_base = 0,
                                .hash_func = {
                                    .sha_init = soft_sha_init,
                                    .sha_core = soft_sha_core,
                                    .sha_finish = soft_sha_finish,
                                }};

TEST_GROUP(soft_hmac);

TEST_SETUP(soft_hmac) {}

TEST_TEAR_DOWN(soft_hmac) {}

/* HMAC sha 224 */
TEST(soft_hmac, soft_hmac_sha224_keysize_shorter_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xBA, 0x38, 0xA2, 0x45, 0x7B, 0x23, 0x5C, 0x65, 0x7D, 0x91, 0xDA,
        0x19, 0xAD, 0x18, 0x42, 0x5B, 0x1A, 0xD9, 0x13, 0x28, 0xF6, 0xDA,
        0xF9, 0x6C, 0x5C, 0x82, 0x95, 0x50, 0x21, 0xDA, 0x24, 0xBA, 0xC6,
        0x70, 0xBB, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xFD, 0x61,
        0x28, 0xC0, 0x62, 0x60, 0xF8, 0xF6, 0xEC, 0xC9, 0x32, 0xEC, 0x6F,
        0x1A, 0x5B, 0xF5, 0x57, 0x3C, 0x3B, 0x08, 0x58};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA224_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA224_BYTE_HASHSIZE] = {
        0xEE, 0xD5, 0x4E, 0x65, 0xA4, 0x97, 0x73, 0x54, 0xB9, 0x18,
        0x00, 0xFB, 0x1A, 0xE2, 0x63, 0xEF, 0xB1, 0xDE, 0xEC, 0x9D,
        0x61, 0x96, 0x1B, 0x1D, 0x70, 0x4D, 0xAE, 0x0B};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA224, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha224_keysize_equal_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xBA, 0x38, 0xA2, 0x45, 0x7B, 0x23, 0x5C, 0x65, 0x7D, 0x91, 0xDA,
        0x19, 0xAD, 0x18, 0x42, 0x5B, 0x1A, 0xD9, 0x13, 0x28, 0xF6, 0xDA,
        0xF9, 0x6C, 0x5C, 0x82, 0x95, 0x50, 0x21, 0xDA, 0x24, 0xBA, 0xC6,
        0x70, 0xBB, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xFD, 0x61,
        0x28, 0xC0, 0x62, 0x60, 0xF8, 0xF6, 0xEC, 0xC9, 0x32, 0xEC, 0x6F,
        0x1A, 0x5B, 0xF5, 0x57, 0x3C, 0x3B, 0x08, 0x58, 0xBB};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA224_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA224_BYTE_HASHSIZE] = {
        0x55, 0x0F, 0x13, 0x3E, 0x80, 0xE2, 0x91, 0x73, 0x7C, 0x22,
        0xE5, 0x42, 0xF0, 0x27, 0x8D, 0x90, 0x85, 0x31, 0x6D, 0x35,
        0x14, 0x74, 0x90, 0xD8, 0x63, 0xB8, 0x81, 0x8B};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA224, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha224_keysize_greater_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xBA, 0x38, 0xA2, 0x45, 0x7B, 0x23, 0x5C, 0x65, 0x7D, 0x91, 0xDA,
        0x19, 0xAD, 0x18, 0x42, 0x5B, 0x1A, 0xD9, 0x13, 0x28, 0xF6, 0xDA,
        0xF9, 0x6C, 0x5C, 0x82, 0x95, 0x50, 0x21, 0xDA, 0x24, 0xBA, 0xC6,
        0x70, 0xBB, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xFD, 0x61,
        0x28, 0xC0, 0x62, 0x60, 0xF8, 0xF6, 0xEC, 0xC9, 0x32, 0xEC, 0x6F,
        0x1A, 0x5B, 0xF5, 0x57, 0x3C, 0x3B, 0x08, 0x58, 0xBB, 0x04};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA224_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA224_BYTE_HASHSIZE] = {
        0x9c, 0xf0, 0x4d, 0x0a, 0xe8, 0x60, 0x4c, 0x68, 0xed, 0x38,
        0xc7, 0x9a, 0x9b, 0x9a, 0xd8, 0x7f, 0xb6, 0x50, 0x60, 0x22,
        0xda, 0x4c, 0xb2, 0xa4, 0x60, 0x6c, 0xdc, 0x29};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA224, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA224_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

/* HMAC sha 256 */
TEST(soft_hmac, soft_hmac_sha256_keysize_shorter_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xBA, 0x38, 0xA2, 0x45, 0x7B, 0x23, 0x5C, 0x65, 0x7D, 0x91, 0xDA,
        0x19, 0xAD, 0x18, 0x42, 0x5B, 0x1A, 0xD9, 0x13, 0x28, 0xF6, 0xDA,
        0xF9, 0x6C, 0x5C, 0x82, 0x95, 0x50, 0x21, 0xDA, 0x24, 0xBA, 0xC6,
        0x70, 0xBB, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xFD, 0x61,
        0x28, 0xC0, 0x62, 0x60, 0xF8, 0xF6, 0xEC, 0xC9, 0x32, 0xEC, 0x6F,
        0x1A, 0x5B, 0xF5, 0x57, 0x3C, 0x3B, 0x08, 0x58};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA256_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA256_BYTE_HASHSIZE] = {
        0x60, 0x2a, 0x0a, 0xef, 0xf1, 0x77, 0x5a, 0x02, 0x11, 0x17, 0xa3,
        0x09, 0xa2, 0x63, 0x9d, 0x8b, 0xde, 0xab, 0xb2, 0xec, 0x74, 0x94,
        0xa3, 0x59, 0xad, 0x78, 0x05, 0x6c, 0xd3, 0x5a, 0x37, 0x2f};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA256, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA256_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha256_keysize_equal_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xBA, 0x38, 0xA2, 0x45, 0x7B, 0x23, 0x5C, 0x65, 0x7D, 0x91, 0xDA,
        0x19, 0xAD, 0x18, 0x42, 0x5B, 0x1A, 0xD9, 0x13, 0x28, 0xF6, 0xDA,
        0xF9, 0x6C, 0x5C, 0x82, 0x95, 0x50, 0x21, 0xDA, 0x24, 0xBA, 0xC6,
        0x70, 0xBB, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xFD, 0x61,
        0x28, 0xC0, 0x62, 0x60, 0xF8, 0xF6, 0xEC, 0xC9, 0x32, 0xEC, 0x6F,
        0x1A, 0x5B, 0xF5, 0x57, 0x3C, 0x3B, 0x08, 0x58, 0xBB};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA256_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA256_BYTE_HASHSIZE] = {
        0x1e, 0x78, 0x2f, 0xca, 0x6f, 0x26, 0x69, 0x2b, 0xcb, 0x5d, 0xde,
        0x12, 0xf1, 0x86, 0x70, 0xcb, 0x73, 0x46, 0x0b, 0x50, 0xcf, 0xa2,
        0x16, 0x62, 0xa3, 0x3a, 0x66, 0x77, 0x0e, 0xdb, 0xe5, 0x77};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA256, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA256_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha256_keysize_greater_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xBA, 0x38, 0xA2, 0x45, 0x7B, 0x23, 0x5C, 0x65, 0x7D, 0x91, 0xDA,
        0x19, 0xAD, 0x18, 0x42, 0x5B, 0x1A, 0xD9, 0x13, 0x28, 0xF6, 0xDA,
        0xF9, 0x6C, 0x5C, 0x82, 0x95, 0x50, 0x21, 0xDA, 0x24, 0xBA, 0xC6,
        0x70, 0xBB, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xFD, 0x61,
        0x28, 0xC0, 0x62, 0x60, 0xF8, 0xF6, 0xEC, 0xC9, 0x32, 0xEC, 0x6F,
        0x1A, 0x5B, 0xF5, 0x57, 0x3C, 0x3B, 0x08, 0x58, 0xBB, 0x04};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA256_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA256_BYTE_HASHSIZE] = {
        0xde, 0x20, 0xa8, 0x60, 0x46, 0xc2, 0xc2, 0xdf, 0xa8, 0x53, 0xaf,
        0x58, 0x83, 0x74, 0xfd, 0x85, 0xf7, 0x59, 0xcf, 0x4d, 0x88, 0xa2,
        0x65, 0x65, 0xf6, 0xa1, 0xf1, 0x8f, 0x5d, 0x7e, 0x80, 0xfc};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA256, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA256_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

/* HMAC sha 384 */
TEST(soft_hmac, soft_hmac_sha384_keysize_shorter_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65, 0x7d, 0x91, 0xda, 0x19,
        0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28, 0xf6, 0xda, 0xf9, 0x6c,
        0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba, 0xc6, 0x70, 0xbb, 0x86,
        0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61, 0x28, 0xc0, 0x62, 0x60,
        0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a, 0x5b, 0xf5, 0x57, 0x3c,
        0x3b, 0x08, 0x58, 0xbb, 0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65,
        0x7d, 0x91, 0xda, 0x19, 0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28,
        0xf6, 0xda, 0xf9, 0x6c, 0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba,
        0xc6, 0x70, 0xbb, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61,
        0x28, 0xc0, 0x62, 0x60, 0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a,
        0x5b, 0xf5, 0x57, 0x3c, 0x3b, 0x08, 0x58};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA384_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA384_BYTE_HASHSIZE] = {
        0x91, 0x7e, 0x3e, 0x34, 0xf6, 0xae, 0x2e, 0xa0, 0xbf, 0xd0, 0x92, 0x21,
        0xd5, 0x5d, 0xc1, 0x7c, 0x75, 0x33, 0xb4, 0x1d, 0x9e, 0x9c, 0x8b, 0xc9,
        0xdc, 0x87, 0x9c, 0xf4, 0x0a, 0xce, 0xa4, 0xf6, 0x6f, 0x92, 0x82, 0x02,
        0xe4, 0x82, 0x36, 0x56, 0xe2, 0xeb, 0x67, 0x2e, 0xb1, 0x63, 0x83, 0x91};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA384, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha384_keysize_equal_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65, 0x7d, 0x91, 0xda, 0x19,
        0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28, 0xf6, 0xda, 0xf9, 0x6c,
        0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba, 0xc6, 0x70, 0xbb, 0x86,
        0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61, 0x28, 0xc0, 0x62, 0x60,
        0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a, 0x5b, 0xf5, 0x57, 0x3c,
        0x3b, 0x08, 0x58, 0xbb, 0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65,
        0x7d, 0x91, 0xda, 0x19, 0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28,
        0xf6, 0xda, 0xf9, 0x6c, 0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba,
        0xc6, 0x70, 0xbb, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61,
        0x28, 0xc0, 0x62, 0x60, 0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a,
        0x5b, 0xf5, 0x57, 0x3c, 0x3b, 0x08, 0x58, 0xbb};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA384_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA384_BYTE_HASHSIZE] = {
        0x16, 0x5b, 0x04, 0xcf, 0xb2, 0x36, 0x18, 0xb0, 0x16, 0x8c, 0x06, 0x10,
        0xf7, 0x12, 0xd9, 0x92, 0x96, 0x31, 0x98, 0x0c, 0x58, 0xa7, 0x1d, 0x1f,
        0x0e, 0xb7, 0x82, 0x98, 0xf6, 0x27, 0x86, 0xf9, 0x31, 0x9c, 0xc9, 0xe5,
        0xee, 0x75, 0xdd, 0xc8, 0xa3, 0xf8, 0x21, 0x72, 0x6c, 0xab, 0x71, 0xf4};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA384, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha384_keysize_greater_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65, 0x7d, 0x91, 0xda, 0x19,
        0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28, 0xf6, 0xda, 0xf9, 0x6c,
        0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba, 0xc6, 0x70, 0xbb, 0x86,
        0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61, 0x28, 0xc0, 0x62, 0x60,
        0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a, 0x5b, 0xf5, 0x57, 0x3c,
        0x3b, 0x08, 0x58, 0xbb, 0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65,
        0x7d, 0x91, 0xda, 0x19, 0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28,
        0xf6, 0xda, 0xf9, 0x6c, 0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba,
        0xc6, 0x70, 0xbb, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61,
        0x28, 0xc0, 0x62, 0x60, 0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a,
        0x5b, 0xf5, 0x57, 0x3c, 0x3b, 0x08, 0x58, 0xbb, 0x04};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA384_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA384_BYTE_HASHSIZE] = {
        0xfa, 0x6a, 0xd1, 0xef, 0x36, 0x77, 0x4a, 0x80, 0xcf, 0xdf, 0x9d, 0xcc,
        0x14, 0x07, 0x52, 0xf1, 0x56, 0x5d, 0x77, 0x17, 0x9f, 0x33, 0xd4, 0x93,
        0xae, 0x31, 0x9f, 0x03, 0x5b, 0x05, 0x10, 0x42, 0x36, 0x72, 0xa9, 0xd5,
        0x72, 0x37, 0x76, 0x58, 0xab, 0x71, 0xff, 0xf7, 0x8b, 0x98, 0x52, 0x3a};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA384, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA384_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

/* HMAC sha 512 */
TEST(soft_hmac, soft_hmac_sha512_keysize_shorter_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65, 0x7d, 0x91, 0xda, 0x19,
        0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28, 0xf6, 0xda, 0xf9, 0x6c,
        0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba, 0xc6, 0x70, 0xbb, 0x86,
        0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61, 0x28, 0xc0, 0x62, 0x60,
        0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a, 0x5b, 0xf5, 0x57, 0x3c,
        0x3b, 0x08, 0x58, 0xbb, 0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65,
        0x7d, 0x91, 0xda, 0x19, 0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28,
        0xf6, 0xda, 0xf9, 0x6c, 0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba,
        0xc6, 0x70, 0xbb, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61,
        0x28, 0xc0, 0x62, 0x60, 0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a,
        0x5b, 0xf5, 0x57, 0x3c, 0x3b, 0x08, 0x58};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA512_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA512_BYTE_HASHSIZE] = {
        0x15, 0x06, 0x4a, 0xb1, 0x48, 0x44, 0x2e, 0x7b, 0x37, 0xd3, 0x6b,
        0x97, 0x16, 0xfb, 0xfc, 0x11, 0xee, 0xc6, 0xbe, 0xdc, 0x42, 0x77,
        0x7e, 0xdc, 0x86, 0xc4, 0x21, 0x5d, 0x20, 0x03, 0x16, 0xab, 0x1b,
        0x9e, 0xf4, 0x6a, 0xa6, 0xef, 0xb7, 0xfd, 0x9d, 0x84, 0xcf, 0xfe,
        0x3d, 0x3c, 0x7c, 0x79, 0xdf, 0x93, 0xeb, 0x20, 0x98, 0xe8, 0x28,
        0x2c, 0x8f, 0x35, 0x06, 0xd6, 0xae, 0xbb, 0xcb, 0x95};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA512, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA512_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha512_keysize_equal_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65, 0x7d, 0x91, 0xda, 0x19,
        0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28, 0xf6, 0xda, 0xf9, 0x6c,
        0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba, 0xc6, 0x70, 0xbb, 0x86,
        0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61, 0x28, 0xc0, 0x62, 0x60,
        0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a, 0x5b, 0xf5, 0x57, 0x3c,
        0x3b, 0x08, 0x58, 0xbb, 0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65,
        0x7d, 0x91, 0xda, 0x19, 0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28,
        0xf6, 0xda, 0xf9, 0x6c, 0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba,
        0xc6, 0x70, 0xbb, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61,
        0x28, 0xc0, 0x62, 0x60, 0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a,
        0x5b, 0xf5, 0x57, 0x3c, 0x3b, 0x08, 0x58, 0xbb};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA512_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA512_BYTE_HASHSIZE] = {
        0xb0, 0x6f, 0x2e, 0x46, 0x37, 0x3c, 0x89, 0x62, 0xbc, 0x2c, 0x08,
        0x43, 0xa5, 0x77, 0x04, 0x39, 0x43, 0x18, 0x1b, 0xdb, 0xa9, 0x42,
        0x27, 0x6b, 0x9e, 0xd3, 0x2f, 0xeb, 0x5d, 0x1b, 0x2a, 0xd0, 0x99,
        0x9d, 0x5b, 0x43, 0x70, 0xfa, 0x21, 0xe3, 0x5d, 0xf8, 0x3b, 0xc5,
        0xb5, 0x9c, 0xff, 0xcf, 0x70, 0xa4, 0x0b, 0xc3, 0x50, 0x15, 0x45,
        0x76, 0x1c, 0xeb, 0x57, 0xf9, 0xce, 0xd2, 0x25, 0x4b};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA512, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA512_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}

TEST(soft_hmac, soft_hmac_sha512_keysize_greater_than_blocksize)
{
    int32_t result;
    hmac_ctx_t hmac_ctx;
    sha_ctx_t sha_ctx;

    static const uint8_t key[] = {
        0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65, 0x7d, 0x91, 0xda, 0x19,
        0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28, 0xf6, 0xda, 0xf9, 0x6c,
        0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba, 0xc6, 0x70, 0xbb, 0x86,
        0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61, 0x28, 0xc0, 0x62, 0x60,
        0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a, 0x5b, 0xf5, 0x57, 0x3c,
        0x3b, 0x08, 0x58, 0xbb, 0xba, 0x38, 0xa2, 0x45, 0x7b, 0x23, 0x5c, 0x65,
        0x7d, 0x91, 0xda, 0x19, 0xad, 0x18, 0x42, 0x5b, 0x1a, 0xd9, 0x13, 0x28,
        0xf6, 0xda, 0xf9, 0x6c, 0x5c, 0x82, 0x95, 0x50, 0x21, 0xda, 0x24, 0xba,
        0xc6, 0x70, 0xbb, 0x86, 0x61, 0x61, 0x47, 0x12, 0x20, 0x15, 0xfd, 0x61,
        0x28, 0xc0, 0x62, 0x60, 0xf8, 0xf6, 0xec, 0xc9, 0x32, 0xec, 0x6f, 0x1a,
        0x5b, 0xf5, 0x57, 0x3c, 0x3b, 0x08, 0x58, 0xbb, 0x04};

    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t mac[SHA512_BYTE_HASHSIZE];
    size_t mac_len = sizeof(mac);

    static const uint8_t expected_mac[SHA512_BYTE_HASHSIZE] = {
        0x6b, 0x20, 0x05, 0xbd, 0x35, 0xc0, 0x21, 0x92, 0x57, 0x23, 0x3c,
        0x30, 0x00, 0x7b, 0x63, 0xed, 0x75, 0x93, 0x22, 0x55, 0xe3, 0xe7,
        0x9e, 0xd5, 0x6c, 0x91, 0xfe, 0xbb, 0xbd, 0xb0, 0x69, 0xe8, 0x78,
        0xba, 0xd0, 0x5c, 0xdb, 0x2a, 0x50, 0x9e, 0x6d, 0x43, 0xbb, 0xcf,
        0x3f, 0x0f, 0x9e, 0x90, 0x3d, 0x3a, 0xd4, 0xc8, 0x5f, 0x16, 0xf8,
        0x63, 0x7e, 0x8b, 0xb2, 0x8a, 0x11, 0x46, 0xbf, 0x65};

    result = soft_hmac_init(&scl, &hmac_ctx, &sha_ctx, SCL_HASH_SHA512, key,
                            sizeof(key));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_core(&scl, &hmac_ctx, message, sizeof(message));
    TEST_ASSERT_TRUE(0 == result);

    result = soft_hmac_finish(&scl, &hmac_ctx, mac, &mac_len);
    TEST_ASSERT_TRUE(0 == result);
    TEST_ASSERT_TRUE(SHA512_BYTE_HASHSIZE == mac_len);
    TEST_ASSERT_TRUE(0 == memcmp(expected_mac, mac, sizeof(expected_mac)));
}
