/**
 * @file test_hca_aes_192.c
 * @brief test suite for scl_hca.c with 192 bits key length on ecb, cdc modes
 * @note These tests use HCA (Hardware Cryptographic Accelerator)
 * 
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

static const metal_scl_t scl = {
    .hca_base = METAL_SIFIVE_HCA_0_BASE_ADDRESS,
    .aes_func = {.setkey = hca_aes_setkey,
                 .setiv = hca_aes_setiv,
                 .cipher = hca_aes_cipher,
                 .auth_init = hca_aes_auth_init,
                 .auth_core = hca_aes_auth_core,
                 .auth_finish = hca_aes_auth_finish}};

TEST_GROUP(hca_aes_192);

TEST_SETUP(hca_aes_192) {}

TEST_TEAR_DOWN(hca_aes_192) {}

TEST(hca_aes_192, ecb_F_1_34)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.3 ECB-AES192.Encrypt
     * F.1.4 ECB-AES192.Decrypt
     * key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = bd334f1d6e45f25ff712a214571fa5cc
     *     block2 = 974104846d0ad3ad7734ecb3ecee4eef
     *     block3 = ef7afd2270e2e60adce0ba2face6444e
     *     block4 = 9a4b41ba738d6c72fb16691603c18e0e
     */
    static const uint64_t key192[4] = {0, 0x62f8ead2522c6b7b,
                                       0xc810f32b809079e5, 0x8e73b0f7da0e6452};

    static const uint8_t plaintext_be[64] __attribute__((aligned(8))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2,
        0x14, 0x57, 0x1f, 0xa5, 0xcc, 0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a,
        0xd3, 0xad, 0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef, 0xef,
        0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a, 0xdc, 0xe0, 0xba, 0x2f,
        0xac, 0xe6, 0x44, 0x4e, 0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c,
        0x72, 0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e,
    };

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY192, key192, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.3 ECB-AES192.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_ECB, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            plaintext_be, sizeof(plaintext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));

    memset(tmp, 0, sizeof(tmp));
    /* F.1.4 ECB-AES192.Decrypt */
    result = hca_aes_cipher(&scl, SCL_AES_ECB, SCL_DECRYPT, SCL_BIG_ENDIAN_MODE,
                            ciphertext_be, sizeof(ciphertext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_192, cbc_F_2_34)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.2.3 CBC-AES192.Encrypt
     * F.2.4 CBC-AES192.Decrypt
     * key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
     * IV:  000102030405060708090a0b0c0d0e0f
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext:
     *     block1 = 4f021db243bc633d7178183a9fa071e8
     *     block2 = b4d9ada9ad7dedf4e5e738763f69145a
     *     block3 = 571b242012fb7ae07fa9baac3df102e0
     *     block4 = 08b0e27988598881d920a9e64f5615cd
     */
    static const uint64_t key192[4] = {0, 0x62f8ead2522c6b7b,
                                       0xc810f32b809079e5, 0x8e73b0f7da0e6452};

    static const uint64_t IV[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};

    static const uint8_t plaintext_be[64] __attribute__((aligned(8))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18,
        0x3a, 0x9f, 0xa0, 0x71, 0xe8, 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d,
        0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a, 0x57,
        0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac,
        0x3d, 0xf1, 0x02, 0xe0, 0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88,
        0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd};

    uint8_t tmp[64] __attribute__((aligned(8))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY192, key192, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    result = hca_aes_setiv(&scl, IV);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.2.3 CBC-AES192.Encrypt */
    result = hca_aes_cipher(&scl, SCL_AES_CBC, SCL_ENCRYPT, SCL_BIG_ENDIAN_MODE,
                            plaintext_be, sizeof(plaintext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));

    /* F.2.4 CBC-AES192.Decrypt */
    memset(tmp, 0, sizeof(tmp));
    result = hca_aes_cipher(&scl, SCL_AES_CBC, SCL_DECRYPT, SCL_BIG_ENDIAN_MODE,
                            ciphertext_be, sizeof(ciphertext_be), tmp);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

#endif
