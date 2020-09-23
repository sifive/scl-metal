/**
 * @file test_hca_aes_128.c
 * @brief test suite for scl_hca.c with 128 bits key length on cbc, ccm, cfb,
 * ctr, ecb, gcm and ofb modes
 * @note These tests use HCA (Hardware Cryptographic Accelerator)

 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity.h"
#include "unity_fixture.h"

#include <string.h>

#include <api/blockcipher/aes/aes.h>
#include <api/hardware/scl_hca.h>
#include <api/scl_api.h>

#include <metal/machine/platform.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)

#define CCM_TQ(t, q) ((uint8_t)((uint8_t)((t) & 0xF) + (uint8_t)((q) << 4)))

static const metal_scl_t scl = {
    .hca_base = METAL_SIFIVE_HCA_0_BASE_ADDRESS,
    .aes_func = {.setkey = hca_aes_setkey,
                 .setiv = hca_aes_setiv,
                 .cipher = hca_aes_cipher,
                 .auth_init = hca_aes_auth_init,
                 .auth_core = hca_aes_auth_core,
                 .auth_finish = hca_aes_auth_finish}};

TEST_GROUP(hca_aes_128);

TEST_SETUP(hca_aes_128) {}

TEST_TEAR_DOWN(hca_aes_128) {}

TEST(hca_aes_128, ecb_F_1_12)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.1 ECB-AES128.Encrypt
     * F.1.2 ECB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3ad77bb40d7a3660a89ecaf32466ef97
     *     block2 = f5d3d58503b9699de785895a96fdbaaf
     *     block3 = 43b1cd7f598ece23881b00e3ed030688
     *     block4 = 7b0c785e27e8ad3f8223207104725dd4
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint8_t plaintext_be[64] __attribute__((aligned(8))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
        0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
        0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43,
        0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3,
        0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad,
        0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_ECB, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            plaintext_be, sizeof(plaintext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    memset(tmp, 0, sizeof(tmp));
    /* F.1.2 ECB-AES128.Decrypt */
    result = hca_aes_cipher(&scl, SCL_AES_ECB, SCL_DECRYPT, SCL_BIG_ENDIAN_MODE,
                            ciphertext_be, sizeof(ciphertext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_128, ecb_not_aligned)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.1 ECB-AES128.Encrypt
     * F.1.2 ECB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3ad77bb40d7a3660a89ecaf32466ef97
     *     block2 = f5d3d58503b9699de785895a96fdbaaf
     *     block3 = 43b1cd7f598ece23881b00e3ed030688
     *     block4 = 7b0c785e27e8ad3f8223207104725dd4
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint8_t plaintext_be[65] __attribute__((aligned(8))) = {
        0x00, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
        0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e,
        0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1,
        0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f,
        0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
        0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
        0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43,
        0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3,
        0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad,
        0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_ECB, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            &plaintext_be[1], sizeof(plaintext_be) - 1, tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
}

TEST(hca_aes_128, cbc_F_2_12)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.2.1 CBC-AES128.Encrypt
     * F.2.2 CBC-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * IV:  000102030405060708090a0b0c0d0e0f
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = 7649abac8119b246cee98e9b12e9197d
     *     block2 = 5086cb9b507219ee95db113a917678b2
     *     block3 = 73bed6b8e3c1743b7116e69e22229516
     *     block4 = 3ff1caa1681fac09120eca307586e1a7
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint64_t IV[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};

    static const uint8_t plaintext_be[64] __attribute__((aligned(8))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e,
        0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72,
        0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73,
        0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e,
        0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac,
        0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.2.1 CBC-AES128.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_CBC, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            plaintext_be, sizeof(plaintext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));

    /* F.2.2 CBC-AES128.Decrypt */
    memset(tmp, 0, sizeof(tmp));
    result = hca_aes_cipher(&scl, SCL_AES_CBC, SCL_DECRYPT, SCL_BIG_ENDIAN_MODE,
                            ciphertext_be, sizeof(ciphertext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_128, cfb_F_3_1314)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.3.13 CFB128-AES128.Encrypt
     * F.3.14 CFB128-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * IV:  000102030405060708090a0b0c0d0e0f
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3b3fd92eb72dad20333449f8e83cfb4a
     *     block2 = c8a64537a0b3a93fcde3cdad9f1ce58b
     *     block3 = 26751f67a3cbb140b1808cf187a4f4df
     *     block4 = c04b05357c5d1c0eeac4c66f9ff7f2e6
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint64_t IV[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};

    static const uint8_t plaintext_be[64] __attribute__((aligned(8))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49,
        0xf8, 0xe8, 0x3c, 0xfb, 0x4a, 0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3,
        0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b, 0x26,
        0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40, 0xb1, 0x80, 0x8c, 0xf1,
        0x87, 0xa4, 0xf4, 0xdf, 0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c,
        0x0e, 0xea, 0xc4, 0xc6, 0x6f, 0x9f, 0xf7, 0xf2, 0xe6};

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.3.13 CFB-AES128.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_CFB, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            plaintext_be, sizeof(plaintext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));

    /* F.3.14 CFB-AES128.Decrypt */
    memset(tmp, 0, sizeof(tmp));
    result = hca_aes_cipher(&scl, SCL_AES_CFB, SCL_DECRYPT, SCL_BIG_ENDIAN_MODE,
                            ciphertext_be, sizeof(ciphertext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_128, ofb_F_4_12)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.4.1 OFB-AES128.Encrypt
     * F.4.2 OFB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * IV:  000102030405060708090a0b0c0d0e0f
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3b3fd92eb72dad20333449f8e83cfb4a
     *     block2 = 7789508d16918f03f53c52dac54ed825
     *     block3 = 9740051e9c5fecf64344f7a82260edcc
     *     block4 = 304c6528f659c77866a510d9c1d6ae5e
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint64_t IV[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};

    static const uint8_t plaintext_be[64] __attribute__((aligned(8))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49,
        0xf8, 0xe8, 0x3c, 0xfb, 0x4a, 0x77, 0x89, 0x50, 0x8d, 0x16, 0x91,
        0x8f, 0x03, 0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25, 0x97,
        0x40, 0x05, 0x1e, 0x9c, 0x5f, 0xec, 0xf6, 0x43, 0x44, 0xf7, 0xa8,
        0x22, 0x60, 0xed, 0xcc, 0x30, 0x4c, 0x65, 0x28, 0xf6, 0x59, 0xc7,
        0x78, 0x66, 0xa5, 0x10, 0xd9, 0xc1, 0xd6, 0xae, 0x5e};

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.4.1 OFB-AES128.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_OFB, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            plaintext_be, sizeof(plaintext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));

    /* F.4.2 OFB-AES128.Decrypt */
    memset(tmp, 0, sizeof(tmp));
    result = hca_aes_cipher(&scl, SCL_AES_OFB, SCL_DECRYPT, SCL_BIG_ENDIAN_MODE,
                            ciphertext_be, sizeof(ciphertext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_128, ctr_F_5_12)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.5.1 OFB-AES128.Encrypt
     * F.5.2 OFB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * IV:  f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = 874d6191b620e3261bef6864990db6ce
     *     block2 = 9806f66b7970fdff8617187bb9fffdff
     *     block3 = 5ae4df3edbd5d35e5b4f09020db03eab
     *     block4 = 1e031dda2fbe03d1792170a0f3009cee
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint64_t IV[2] = {0xf8f9fafbfcfdfeff, 0xf0f1f2f3f4f5f6f7};

    static const uint8_t plaintext_be[64] __attribute__((aligned(8))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68,
        0x64, 0x99, 0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70,
        0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff, 0x5a,
        0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02,
        0x0d, 0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03,
        0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee};

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.5.1 CTR-AES128.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_CTR, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            plaintext_be, sizeof(plaintext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));

    /* F.5.2 CTR-AES128.Decrypt */
    memset(tmp, 0, sizeof(tmp));
    result = hca_aes_cipher(&scl, SCL_AES_CTR, SCL_DECRYPT, SCL_BIG_ENDIAN_MODE,
                            ciphertext_be, sizeof(ciphertext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_128, ccm_1)
{
    /*
     * key: d24a3d3dde8c84830280cb87abad0bb3
     * IV:  f1100035bb24a8d26004e0e24b
     * AAD:
     * Payload:
     *     block1 = 7c86135ed9c2a515aaae0e9a20813389
     *     block2 = 7269220f30870006
     * Ciphertext:
     *     block1 = 1faeb0ee2ca2cd52f0aa3966578344f2
     *     block2 = 4e69b742c4ab37ab
     * Tag: 1123301219c70599 b7c373ad4b3ad67b
     */
    static const uint64_t key128[4] = {0, 0, 0x0280cb87abad0bb3,
                                       0xd24a3d3dde8c8483};

    static const uint64_t IV[2] = {0x6004e0e24b000000, 0xf1100035bb24a8d2};

    static const uint8_t payload_be[24] __attribute__((aligned(8))) = {
        0x7c, 0x86, 0x13, 0x5e, 0xd9, 0xc2, 0xa5, 0x15, 0xaa, 0xae, 0x0e, 0x9a,
        0x20, 0x81, 0x33, 0x89, 0x72, 0x69, 0x22, 0x0f, 0x30, 0x87, 0x00, 0x06};

    static const uint8_t ciphertext_be[24] __attribute__((aligned(8))) = {
        0x1f, 0xae, 0xb0, 0xee, 0x2c, 0xa2, 0xcd, 0x52, 0xf0, 0xaa, 0x39, 0x66,
        0x57, 0x83, 0x44, 0xf2, 0x4e, 0x69, 0xb7, 0x42, 0xc4, 0xab, 0x37, 0xab};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0xb7c373ad4b3ad67b, 0x1123301219c70599};

    uint8_t tmp[24] __attribute__((aligned(8))) = {0};
    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    int32_t result = 0;
    size_t len;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_CCM, SCL_ENCRYPT,
                               SCL_BIG_ENDIAN_MODE, CCM_TQ(7, 2), NULL, 0,
                               sizeof(payload_be));
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_core(&scl, &ctx_aes_auth, payload_be,
                               sizeof(payload_be), tmp, &len);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, len);

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, &tmp[len], tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}

TEST(hca_aes_128, ccm_2)
{
    /*
     * key: 2ebf60f0969013a5 4a3dedb19d20f6c8
     * IV:  1de8c5e21f9db331 23ff870add
     * AAD:
     *     block1 = e1de6c6119d7db471136285d10b47a45
     *     block2 = 0221b16978569190ef6a22b055295603
     * Payload:
     * Ciphertext:
     * Tag: 0ead29ef205fbb86 d11abe5ed704b880
     */
    static const uint64_t key128[4] = {0, 0, 0x4a3dedb19d20f6c8,
                                       0x2ebf60f0969013a5};

    static const uint64_t IV[2] = {0x23ff870add000000, 0x1de8c5e21f9db331};

    static const uint8_t aad_be[32] __attribute__((aligned(8))) = {
        0xe1, 0xde, 0x6c, 0x61, 0x19, 0xd7, 0xdb, 0x47, 0x11, 0x36, 0x28,
        0x5d, 0x10, 0xb4, 0x7a, 0x45, 0x02, 0x21, 0xb1, 0x69, 0x78, 0x56,
        0x91, 0x90, 0xef, 0x6a, 0x22, 0xb0, 0x55, 0x29, 0x56, 0x03};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0xd11abe5ed704b880, 0x0ead29ef205fbb86};

    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_CCM, SCL_ENCRYPT,
                               SCL_BIG_ENDIAN_MODE, CCM_TQ(7, 2), aad_be,
                               sizeof(aad_be), 0);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, NULL, tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}

TEST(hca_aes_128, ccm_3)
{
    /*
     * key: 10a7720f2e18f739 c26924925af6b670
     * IV:  8c4e7813ab9bce9d afee01c628
     * AAD:
     *     block1 = a209941fab710fda38d11c68b13d930f
     * Payload:
     *     block1 = e59782a9aea45f467b90e51a0fdf166b
     *     block2 = aba05663def2d8b6
     * Ciphertext:
     *     block1 = e357b1ccdaca6f3506dc45279c2e4c59
     *     block2 = f5307a5fd6a99cd7
     * Tag: 2341ea8c07855699 73f90ee9ee645acc
     */
    static const uint64_t key128[4] = {0, 0, 0xc26924925af6b670,
                                       0x10a7720f2e18f739};

    static const uint64_t IV[2] = {0xafee01c628000000, 0x8c4e7813ab9bce9d};

    static const uint8_t aad_be[16] __attribute__((aligned(8))) = {
        0xa2, 0x09, 0x94, 0x1f, 0xab, 0x71, 0x0f, 0xda,
        0x38, 0xd1, 0x1c, 0x68, 0xb1, 0x3d, 0x93, 0x0f};

    static const uint8_t payload_be[24] __attribute__((aligned(8))) = {
        0xe5, 0x97, 0x82, 0xa9, 0xae, 0xa4, 0x5f, 0x46, 0x7b, 0x90, 0xe5, 0x1a,
        0x0f, 0xdf, 0x16, 0x6b, 0xab, 0xa0, 0x56, 0x63, 0xde, 0xf2, 0xd8, 0xb6};

    static const uint8_t ciphertext_be[24] __attribute__((aligned(8))) = {
        0xe3, 0x57, 0xb1, 0xcc, 0xda, 0xca, 0x6f, 0x35, 0x06, 0xdc, 0x45, 0x27,
        0x9c, 0x2e, 0x4c, 0x59, 0xf5, 0x30, 0x7a, 0x5f, 0xd6, 0xa9, 0x9c, 0xd7};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0x73f90ee9ee645acc, 0x2341ea8c07855699};

    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    uint8_t tmp[24] __attribute__((aligned(8))) = {0};
    int32_t result = 0;
    size_t len;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_CCM, SCL_ENCRYPT,
                               SCL_BIG_ENDIAN_MODE, CCM_TQ(7, 2), aad_be,
                               sizeof(aad_be), sizeof(payload_be));
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_core(&scl, &ctx_aes_auth, payload_be,
                               sizeof(payload_be), tmp, &len);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, len);

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, &tmp[len], tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}

TEST(hca_aes_128, ccm_4)
{
    /*
     * key: 35b403a152120970 85d6e2b77ec3d4f2
     * IV:  daa423bf9256c3fc c347a293aa
     * AAD:
     *     block1 = d3c0ed74e5f25e4c1e479e1a51182bb0
     *     block2 = 18698ec267269149
     * Payload:
     *     block1 = 7dd7396db6613eb80909a3b8c0029b62
     *     block2 = 4912aabedda0659b
     * Ciphertext:
     *     block1 = 5b00cf8a66baa7fe22502ed6f4861af7
     *     block2 = 1fa64b550d643f95
     * Tag: eee82c19ecba3428 0604b58d92dacd3f
     */
    static const uint64_t key128[4] = {0, 0, 0x85d6e2b77ec3d4f2,
                                       0x35b403a152120970};

    static const uint64_t IV[2] = {0xc347a293aa000000, 0xdaa423bf9256c3fc};

    static const uint8_t aad_be[24] __attribute__((aligned(8))) = {
        0xd3, 0xc0, 0xed, 0x74, 0xe5, 0xf2, 0x5e, 0x4c, 0x1e, 0x47, 0x9e, 0x1a,
        0x51, 0x18, 0x2b, 0xb0, 0x18, 0x69, 0x8e, 0xc2, 0x67, 0x26, 0x91, 0x49};

    static const uint8_t payload_be[24] __attribute__((aligned(8))) = {
        0x7d, 0xd7, 0x39, 0x6d, 0xb6, 0x61, 0x3e, 0xb8, 0x09, 0x09, 0xa3, 0xb8,
        0xc0, 0x02, 0x9b, 0x62, 0x49, 0x12, 0xaa, 0xbe, 0xdd, 0xa0, 0x65, 0x9b};

    static const uint8_t ciphertext_be[24] __attribute__((aligned(8))) = {
        0x5b, 0x00, 0xcf, 0x8a, 0x66, 0xba, 0xa7, 0xfe, 0x22, 0x50, 0x2e, 0xd6,
        0xf4, 0x86, 0x1a, 0xf7, 0x1f, 0xa6, 0x4b, 0x55, 0x0d, 0x64, 0x3f, 0x95};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0x0604b58d92dacd3f, 0xeee82c19ecba3428};

    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    uint8_t tmp[24] __attribute__((aligned(8))) = {0};
    int32_t result = 0;
    size_t len;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_CCM, SCL_ENCRYPT,
                               SCL_BIG_ENDIAN_MODE, CCM_TQ(7, 2), aad_be,
                               sizeof(aad_be), sizeof(payload_be));
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_core(&scl, &ctx_aes_auth, payload_be,
                               sizeof(payload_be), tmp, &len);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, len);

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, &tmp[len], tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}

TEST(hca_aes_128, ccm_4b)
{
    /*
     * key: 35b403a152120970 85d6e2b77ec3d4f2
     * IV:  daa423bf9256c3fc c347a293aa
     * AAD:
     *     block1 = d3c0ed74e5f25e4c1e479e1a51182bb0
     *     block2 = 18698ec267269149
     * Payload:
     *     block1 = 7dd7396db6613eb80909a3b8c0029b62
     *     block2 = 4912aabedda0659b
     * Ciphertext:
     *     block1 = 5b00cf8a66baa7fe22502ed6f4861af7
     *     block2 = 1fa64b550d643f95
     * Tag: eee82c19ecba3428 0604b58d92dacd3f
     */
    static const uint64_t key128[4] = {0, 0, 0x85d6e2b77ec3d4f2,
                                       0x35b403a152120970};

    static const uint64_t IV[2] = {0xc347a293aa000000, 0xdaa423bf9256c3fc};

    static const uint64_t aad_le[3] = {0x1e479e1a51182bb0, 0xd3c0ed74e5f25e4c,
                                       0x18698ec267269149};

    static const uint64_t payload_le[3] = {
        0x0909a3b8c0029b62, 0x7dd7396db6613eb8, 0x4912aabedda0659b};

    static const uint64_t ciphertext_le[3] __attribute__((aligned(8))) = {
        0x22502ed6f4861af7, 0x5b00cf8a66baa7fe, 0x1fa64b550d643f95};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0x0604b58d92dacd3f, 0xeee82c19ecba3428};

    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    uint8_t tmp[24] __attribute__((aligned(8))) = {0};
    int32_t result = 0;
    size_t len;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_CCM, SCL_ENCRYPT,
                               SCL_LITTLE_ENDIAN_MODE, CCM_TQ(7, 2),
                               (const uint8_t *)aad_le, sizeof(aad_le),
                               sizeof(payload_le));
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_core(&scl, &ctx_aes_auth, (const uint8_t *)payload_le,
                               sizeof(payload_le), tmp, &len);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_le, tmp, len);

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, &tmp[len], tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_le, tmp, sizeof(ciphertext_le));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}

TEST(hca_aes_128, gcm_1)
{
    /*
     * key: 594157ec4693202b 030f33798b07176d
     * IV:  49b1205408266080 3a1df3df
     * AAD:
     * Payload:
     *     block1 = 3feef98a976a1bd6 34f364ac428bb59c
     *     block2 = d51fb159ec178994 6918dbd50ea6c9d5
     *     block3 = 94a3a31a5269b0da 6936c29d063a5fa2
     *     block4 = cc8a1c
     * Ciphertext:
     *     block1 = c1b7a46a335f23d6 5b8db4008a497969
     *     block2 = 06e225474f4fe7d3 9e55bf2efd97fd82
     *     block3 = d4167de082ae30fa 01e465a601235d8d
     *     block4 = 68bc69
     * Tag: ba92d3661ce8b046 87e8788d55417dc2
     */
    static const uint64_t key128[4] = {0, 0, 0x030f33798b07176d,
                                       0x594157ec4693202b};

    static const uint64_t IV[2] = {0x3a1df3df00000000, 0x49b1205408266080};

    static const uint8_t payload_be[51] __attribute__((aligned(8))) = {
        0x3f, 0xee, 0xf9, 0x8a, 0x97, 0x6a, 0x1b, 0xd6, 0x34, 0xf3, 0x64,
        0xac, 0x42, 0x8b, 0xb5, 0x9c, 0xd5, 0x1f, 0xb1, 0x59, 0xec, 0x17,
        0x89, 0x94, 0x69, 0x18, 0xdb, 0xd5, 0x0e, 0xa6, 0xc9, 0xd5, 0x94,
        0xa3, 0xa3, 0x1a, 0x52, 0x69, 0xb0, 0xda, 0x69, 0x36, 0xc2, 0x9d,
        0x06, 0x3a, 0x5f, 0xa2, 0xcc, 0x8a, 0x1c};

    static const uint8_t ciphertext_be[51] __attribute__((aligned(8))) = {
        0xc1, 0xb7, 0xa4, 0x6a, 0x33, 0x5f, 0x23, 0xd6, 0x5b, 0x8d, 0xb4,
        0x00, 0x8a, 0x49, 0x79, 0x69, 0x06, 0xe2, 0x25, 0x47, 0x4f, 0x4f,
        0xe7, 0xd3, 0x9e, 0x55, 0xbf, 0x2e, 0xfd, 0x97, 0xfd, 0x82, 0xd4,
        0x16, 0x7d, 0xe0, 0x82, 0xae, 0x30, 0xfa, 0x01, 0xe4, 0x65, 0xa6,
        0x01, 0x23, 0x5d, 0x8d, 0x68, 0xbc, 0x69};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0x87e8788d55417dc2, 0xba92d3661ce8b046};

    uint8_t tmp[51] __attribute__((aligned(8))) = {0};
    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    int32_t result = 0;
    size_t len;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result =
        hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_GCM, SCL_ENCRYPT,
                          SCL_BIG_ENDIAN_MODE, 0, NULL, 0, sizeof(payload_be));
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_core(&scl, &ctx_aes_auth, payload_be,
                               sizeof(payload_be), tmp, &len);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, &tmp[len], tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}

TEST(hca_aes_128, gcm_2)
{
    /*
     * key: 99e3e8793e686e57 1d8285c564f75e2b
     * IV:  c2dd0ab868da6aa8 ad9c0d23
     * AAD:
     *     block1 = b668e42d4e444ca8b23cfdd95a9fedd5
     *     block2 = 178aa521144890b093733cf5cf22526c
     *     block3 = 5917ee476541809ac6867a8c399309fc
     * Payload:
     * Ciphertext:
     * Tag: 3f4fba100eaf1f34 b0baadaae9995d85
     */
    static const uint64_t key128[4] = {0, 0, 0x1d8285c564f75e2b,
                                       0x99e3e8793e686e57};

    static const uint64_t IV[2] = {0xad9c0d2300000000, 0xc2dd0ab868da6aa8};

    static const uint8_t aad_be[48] __attribute__((aligned(8))) = {
        0xb6, 0x68, 0xe4, 0x2d, 0x4e, 0x44, 0x4c, 0xa8, 0xb2, 0x3c, 0xfd, 0xd9,
        0x5a, 0x9f, 0xed, 0xd5, 0x17, 0x8a, 0xa5, 0x21, 0x14, 0x48, 0x90, 0xb0,
        0x93, 0x73, 0x3c, 0xf5, 0xcf, 0x22, 0x52, 0x6c, 0x59, 0x17, 0xee, 0x47,
        0x65, 0x41, 0x80, 0x9a, 0xc6, 0x86, 0x7a, 0x8c, 0x39, 0x93, 0x09, 0xfc};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0xb0baadaae9995d85, 0x3f4fba100eaf1f34};

    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result =
        hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_GCM, SCL_ENCRYPT,
                          SCL_BIG_ENDIAN_MODE, 0, aad_be, sizeof(aad_be), 0);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, NULL, tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}

TEST(hca_aes_128, gcm_3)
{
    /*
     * key: 48b7f337cdf9252687ecc760bd8ec184
     * IV:  3e894ebb16ce82a53c3e05b2
     * AAD:
     *     block1 = 7d924cfd37b3d046a96eb5e132042405
     *     block2 = c8731e06509787bbeb41f25827574649
     *     block3 = 5e884d69871f77634c584bb007312234
     * Payload:
     *     block1 = bb2bac67a4709430c39c2eb9acfabc0d
     *     block2 = 456c80d30aa1734e57997d548a8f0603
     * Ciphertext:
     *     block1 = d263228b8ce051f67e9baf1ce7df97d1
     *     block2 = 0cd5f3bc972362055130c7d13c3ab2e7
     * Tag: 71446737ca1fa92e6d026d7d2ed1aa9c
     */
    static const uint64_t key128[4] = {0, 0, 0x87ecc760bd8ec184,
                                       0x48b7f337cdf92526};

    static const uint64_t IV[2] = {0x3c3e05b200000000, 0x3e894ebb16ce82a5};

    static const uint8_t aad_be[48] __attribute__((aligned(8))) = {
        0x7d, 0x92, 0x4c, 0xfd, 0x37, 0xb3, 0xd0, 0x46, 0xa9, 0x6e, 0xb5, 0xe1,
        0x32, 0x04, 0x24, 0x05, 0xc8, 0x73, 0x1e, 0x06, 0x50, 0x97, 0x87, 0xbb,
        0xeb, 0x41, 0xf2, 0x58, 0x27, 0x57, 0x46, 0x49, 0x5e, 0x88, 0x4d, 0x69,
        0x87, 0x1f, 0x77, 0x63, 0x4c, 0x58, 0x4b, 0xb0, 0x07, 0x31, 0x22, 0x34};

    static const uint8_t payload_be[32] __attribute__((aligned(8))) = {
        0xbb, 0x2b, 0xac, 0x67, 0xa4, 0x70, 0x94, 0x30, 0xc3, 0x9c, 0x2e,
        0xb9, 0xac, 0xfa, 0xbc, 0x0d, 0x45, 0x6c, 0x80, 0xd3, 0x0a, 0xa1,
        0x73, 0x4e, 0x57, 0x99, 0x7d, 0x54, 0x8a, 0x8f, 0x06, 0x03};

    static const uint8_t ciphertext_be[32] __attribute__((aligned(8))) = {
        0xd2, 0x63, 0x22, 0x8b, 0x8c, 0xe0, 0x51, 0xf6, 0x7e, 0x9b, 0xaf,
        0x1c, 0xe7, 0xdf, 0x97, 0xd1, 0x0c, 0xd5, 0xf3, 0xbc, 0x97, 0x23,
        0x62, 0x05, 0x51, 0x30, 0xc7, 0xd1, 0x3c, 0x3a, 0xb2, 0xe7};

    static const uint64_t tag[2]
        __attribute__((aligned(8))) = {0x6d026d7d2ed1aa9c, 0x71446737ca1fa92e};

    uint64_t tag_c[2] __attribute__((aligned(8))) = {0};
    uint8_t tmp[32] __attribute__((aligned(8))) = {0};
    int32_t result = 0;
    size_t len;

    aes_auth_ctx_t ctx_aes_auth = {0};

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_init(&scl, &ctx_aes_auth, SCL_AES_GCM, SCL_ENCRYPT,
                               SCL_BIG_ENDIAN_MODE, 0, aad_be, sizeof(aad_be),
                               sizeof(payload_be));
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_auth_core(&scl, &ctx_aes_auth, payload_be,
                               sizeof(payload_be), tmp, &len);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));

    result = hca_aes_auth_finish(&scl, &ctx_aes_auth, NULL, tag_c);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tag, tag_c, sizeof(tag));
}
#endif
