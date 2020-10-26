/**
 * @file test_hca_aes_dma.c
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

#include <backend/api/blockcipher/aes/aes.h>
#include <backend/hardware/scl_hca.h>
#include <backend/api/scl_backend_api.h>

#include <metal/machine/platform.h>
#include <metal/cpu.h>
#include <metal/interrupt.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)

#define SCL_ERR_TIMEOUT     -32768
#define TIMEOUT             6553500

//#define CCM_TQ(t, q) ((uint8_t)((uint8_t)((t) & 0xF) + (uint8_t)((q) << 4)))

static int32_t wrapper_register_handler(const metal_scl_t *const, 
                                        metal_isr_t, void *);

static const metal_scl_t scl = {
    .hca_base = METAL_SIFIVE_HCA_0_BASE_ADDRESS,
    .aes_func = {.setkey = hca_aes_setkey,
                 .setiv = hca_aes_setiv,
                 .cipher = hca_aes_cipher,
                 .cipher_with_dma = hca_aes_cipher_with_dma,
                 .auth_init = hca_aes_auth_init,
                 .auth_core = hca_aes_auth_core,
                 .auth_finish = hca_aes_auth_finish},
    .system_register_handler = wrapper_register_handler
    };

static volatile int32_t unlock = 0;
static volatile int32_t status = 0;
static struct metal_cpu *cpu;
static struct metal_interrupt *cpu_intr;
static struct metal_interrupt *plic;

static void init_metal_irq(void)
{
	/*
	 * Initilize freedom-metal interrupt managment.
	 *   Its SHOULD be made before calling xPortFreeRTOSInit because
	 *   the interrupt/exeception handler MUST be the freertos handler.
	 */
	cpu = metal_cpu_get((unsigned int)metal_cpu_get_current_hartid());
    TEST_ASSERT_NOT_NULL_MESSAGE(cpu, "Cannot get CPU");

	cpu_intr = metal_cpu_interrupt_controller(cpu);
    TEST_ASSERT_NOT_NULL_MESSAGE(cpu_intr, "Cannot get CPU controller");

	metal_interrupt_init(cpu_intr);

	#ifdef METAL_RISCV_PLIC0
    {
        // Check if this target has a plic.
        plic = metal_interrupt_get_controller(METAL_PLIC_CONTROLLER, 0);
        TEST_ASSERT_NOT_NULL_MESSAGE(plic, "Cannot get PLIC");
    }
	#endif /* METAL_RISCV_PLIC0 */

	#ifdef METAL_SIFIVE_CLIC0
    {
        // Check we this target has a clic.
        plic = metal_interrupt_get_controller(METAL_CLIC_CONTROLLER, 0);
        TEST_ASSERT_NOT_NULL_MESSAGE(plic, "Cannot get CLIC");
    }
	#endif /* METAL_SIFIVE_CLIC0 */

    metal_interrupt_init(plic);

}

static int enable_metal_irq(void)
{
    int rc;

    rc = metal_interrupt_enable(cpu_intr, 0);
    TEST_ASSERT_FALSE_MESSAGE(rc, "Cannot enable IRQ");

    return rc;
}

static int disable_metal_irq(void)
{
    int rc;

    rc = metal_interrupt_disable(cpu_intr, 0);
    TEST_ASSERT_FALSE_MESSAGE(rc, "Cannot disable IRQ");

    return rc;
}

static void timer_irq_handler(int id, void *priv_data)
{
    /* Remove compiler warning about unused parameter. */
    (void)id;
    (void)priv_data;

    unlock = 1;
    status = SCL_ERR_TIMEOUT; 
}

static void set_timeout(uint64_t timeout)
{
    // use a timer IRQ, if something going wrong.
    struct metal_interrupt *tmr_intr;
    int rc;

    tmr_intr = metal_cpu_timer_interrupt_controller(cpu);
    if ( !tmr_intr ) {
        return;
    }
    metal_interrupt_init(tmr_intr);

    int tmr_id;
    tmr_id = metal_cpu_timer_get_interrupt_id(cpu);
    rc = metal_interrupt_register_handler(tmr_intr, tmr_id, timer_irq_handler,
                                          cpu);
    TEST_ASSERT_FALSE_MESSAGE(rc, "Cannot register timer IRQ handler");

    metal_cpu_set_mtimecmp(cpu, metal_cpu_get_mtime(cpu) + timeout);
    metal_interrupt_enable(tmr_intr, tmr_id);
    metal_interrupt_enable(cpu_intr, 0);

    unlock = 0;
}

static int32_t wrapper_register_handler(const metal_scl_t *const scl_ptr, 
                                        metal_isr_t func, void *priv_data)
{
    int rc;

    TEST_ASSERT_NOT_NULL_MESSAGE(scl_ptr, "Scl structure is null");

    rc= metal_interrupt_register_handler(plic, METAL_SIFIVE_HCA_CRYPTO_IRQ,
                                     (metal_interrupt_handler_t) func, 
                                     priv_data);
    TEST_ASSERT_FALSE_MESSAGE(rc, "Cannot register IRQ handler");

    rc = metal_interrupt_enable(plic, METAL_SIFIVE_HCA_CRYPTO_IRQ);
    TEST_ASSERT_FALSE_MESSAGE(rc, "Cannot enable CRYPTO IRQ");

    rc = enable_metal_irq();
    return rc;
}

static void finish_callback(int32_t val)
{
    unlock = 1;
    status = val;
}

TEST_GROUP(hca_aes_dma);

TEST_SETUP(hca_aes_dma) { init_metal_irq(); }

TEST_TEAR_DOWN(hca_aes_dma) { disable_metal_irq(); }

TEST(hca_aes_dma, ecb_F_1_12)
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

    static const uint8_t plaintext_be[64] __attribute__((aligned(32))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(32))) = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
        0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
        0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43,
        0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3,
        0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad,
        0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};

    uint8_t tmp[64] __attribute__((aligned(32))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_BIG_ENDIAN_MODE, plaintext_be,
                                     sizeof(plaintext_be), tmp, NULL);
     TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    memset(tmp, 0, sizeof(tmp));
    /* Setup a timeout just in case */
    set_timeout(TIMEOUT);

    /* F.1.2 ECB-AES128.Decrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_DECRYPT, 
                                     SCL_BIG_ENDIAN_MODE, ciphertext_be,
                                     sizeof(ciphertext_be), tmp, finish_callback);
    TEST_ASSERT_TRUE(SCL_OK == result);
    while (0 == unlock);
    TEST_ASSERT_TRUE(SCL_OK == status);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_dma, ecb_F_1_12_half)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.1 ECB-AES128.Encrypt
     * F.1.2 ECB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext:
     *     block1 = 6bc1bee22e409f96e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c9eb76fac45af8e51
     * Ciphertext:
     *     block1 = 3ad77bb40d7a3660a89ecaf32466ef97
     *     block2 = f5d3d58503b9699de785895a96fdbaaf
     *     block3 = 43b1cd7f598ece23881b00e3ed030688
     *     block4 = 7b0c785e27e8ad3f8223207104725dd4
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint8_t plaintext_be[32] __attribute__((aligned(32))) = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};

    static const uint8_t ciphertext_be[32] __attribute__((aligned(32))) = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
        0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
        0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf};

    uint8_t tmp[64] __attribute__((aligned(32))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_BIG_ENDIAN_MODE, plaintext_be,
                                     sizeof(plaintext_be), tmp, NULL);
     TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    memset(tmp, 0, sizeof(tmp));
    /* Setup a timeout just in case */
    set_timeout(TIMEOUT);

    /* F.1.2 ECB-AES128.Decrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_DECRYPT, 
                                     SCL_BIG_ENDIAN_MODE, ciphertext_be,
                                     sizeof(ciphertext_be), tmp, finish_callback);
    TEST_ASSERT_TRUE(SCL_OK == result);
    while (0 == unlock);
    TEST_ASSERT_TRUE(SCL_OK == status);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_be, tmp, sizeof(plaintext_be));
}

TEST(hca_aes_dma, ecb_F_1_12_le)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.1 ECB-AES128.Encrypt
     * F.1.2 ECB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext:
     *     block1 = 6bc1bee22e409f96 e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c 9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411 e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17 ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3ad77bb40d7a3660 a89ecaf32466ef97
     *     block2 = f5d3d58503b9699d e785895a96fdbaaf
     *     block3 = 43b1cd7f598ece23 881b00e3ed030688
     *     block4 = 7b0c785e27e8ad3f 8223207104725dd4
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint64_t plaintext_le[8] __attribute__((aligned(32))) = {
        0xe93d7e117393172a,
        0x6bc1bee22e409f96,
        0x9eb76fac45af8e51,
        0xae2d8a571e03ac9c,
        0xe5fbc1191a0a52ef,
        0x30c81c46a35ce411,
        0xad2b417be66c3710,
        0xf69f2445df4f9b17};

    static const uint64_t ciphertext_le[8] __attribute__((aligned(32))) = {
        0xa89ecaf32466ef97,
        0x3ad77bb40d7a3660,
        0xe785895a96fdbaaf,
        0xf5d3d58503b9699d,
        0x881b00e3ed030688,
        0x43b1cd7f598ece23,
        0x8223207104725dd4,
        0x7b0c785e27e8ad3f};

    uint8_t tmp[64] __attribute__((aligned(32))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_LITTLE_ENDIAN_MODE, (const uint8_t *)plaintext_le,
                                     sizeof(plaintext_le), tmp, NULL);
     TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_le, tmp, sizeof(ciphertext_le));
    memset(tmp, 0, sizeof(tmp));
    /* Setup a timeout just in case */
    set_timeout(TIMEOUT);

    /* F.1.2 ECB-AES128.Decrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_DECRYPT, 
                                     SCL_LITTLE_ENDIAN_MODE, (const uint8_t *)ciphertext_le,
                                     sizeof(ciphertext_le), tmp, finish_callback);
    TEST_ASSERT_TRUE(SCL_OK == result);
    while (0 == unlock);
    TEST_ASSERT_TRUE(SCL_OK == status);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext_le, tmp, sizeof(plaintext_le));
}

TEST(hca_aes_dma, ecb_F_1_12_unalign)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.1 ECB-AES128.Encrypt
     * F.1.2 ECB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext:
     *     block1 = 6bc1bee22e409f96 e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c 9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411 e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17 ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3ad77bb40d7a3660 a89ecaf32466ef97
     *     block2 = f5d3d58503b9699d e785895a96fdbaaf
     *     block3 = 43b1cd7f598ece23 881b00e3ed030688
     *     block4 = 7b0c785e27e8ad3f 8223207104725dd4
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint8_t plaintext_be[83] __attribute__((aligned(32))) = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
        0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
        0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
        0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
        0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
        0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43,
        0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3,
        0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad,
        0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};

    uint8_t tmp[64] __attribute__((aligned(32))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_BIG_ENDIAN_MODE, &plaintext_be[19],
                                     64, tmp, NULL);
     TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    memset(tmp, 0, sizeof(tmp));
    /* Setup a timeout just in case */
    set_timeout(TIMEOUT);

    /* F.1.2 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_BIG_ENDIAN_MODE, &plaintext_be[19],
                                     64, tmp, finish_callback);
    TEST_ASSERT_TRUE(SCL_OK == result);
    while (0 == unlock);
    TEST_ASSERT_TRUE(SCL_OK == status);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
}

TEST(hca_aes_dma, ecb_F_1_12_unalign_2)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.1 ECB-AES128.Encrypt
     * F.1.2 ECB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext:
     *     block1 = 6bc1bee22e409f96 e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c 9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411 e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17 ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3ad77bb40d7a3660 a89ecaf32466ef97
     *     block2 = f5d3d58503b9699d e785895a96fdbaaf
     *     block3 = 43b1cd7f598ece23 881b00e3ed030688
     *     block4 = 7b0c785e27e8ad3f 8223207104725dd4
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint8_t plaintext_be[67] __attribute__((aligned(32))) = {
        0x00, 0x00, 0x00, 
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
        0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
        0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
        0x6c, 0x37, 0x10};

    static const uint8_t ciphertext_be[64] __attribute__((aligned(8))) = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
        0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
        0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43,
        0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3,
        0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad,
        0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};

    uint8_t tmp[64] __attribute__((aligned(32))) = {0};
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_BIG_ENDIAN_MODE, &plaintext_be[3],
                                     64, tmp, NULL);
     TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
    memset(tmp, 0, sizeof(tmp));
    /* Setup a timeout just in case */
    set_timeout(TIMEOUT);

    /* F.1.2 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_BIG_ENDIAN_MODE, &plaintext_be[3],
                                     64, tmp, finish_callback);
    TEST_ASSERT_TRUE(SCL_OK == result);
    while (0 == unlock);
    TEST_ASSERT_TRUE(SCL_OK == status);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_be, tmp, sizeof(ciphertext_be));
}

TEST(hca_aes_dma, ecb_F_1_12_le_unalign)
{
    /* NIST[nistspecialpublication800-38a.pdf]
     * F.1.1 ECB-AES128.Encrypt
     * F.1.2 ECB-AES128.Decrypt
     * key: 2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext:
     *     block1 = 6bc1bee22e409f96 e93d7e117393172a
     *     block2 = ae2d8a571e03ac9c 9eb76fac45af8e51
     *     block3 = 30c81c46a35ce411 e5fbc1191a0a52ef
     *     block4 = f69f2445df4f9b17 ad2b417be66c3710
     * Ciphertext:
     *     block1 = 3ad77bb40d7a3660 a89ecaf32466ef97
     *     block2 = f5d3d58503b9699d e785895a96fdbaaf
     *     block3 = 43b1cd7f598ece23 881b00e3ed030688
     *     block4 = 7b0c785e27e8ad3f 8223207104725dd4
     */
    static const uint64_t key128[4] = {0, 0, 0xabf7158809cf4f3c,
                                       0x2b7e151628aed2a6};

    static const uint64_t plaintext_le[11] __attribute__((aligned(32))) = {
        0x0000000000000000,
        0x0000000000000000,
        0x117393172a000000,
        0xe22e409f96e93d7e,
        0xac45af8e516bc1be,
        0x571e03ac9c9eb76f,
        0x191a0a52efae2d8a,
        0x46a35ce411e5fbc1,
        0x7be66c371030c81c,
        0x45df4f9b17ad2b41,
        0x0000000000f69f24};

    static const uint64_t ciphertext_le[8] __attribute__((aligned(8))) = {
        0xa89ecaf32466ef97,
        0x3ad77bb40d7a3660,
        0xe785895a96fdbaaf,
        0xf5d3d58503b9699d,
        0x881b00e3ed030688,
        0x43b1cd7f598ece23,
        0x8223207104725dd4,
        0x7b0c785e27e8ad3f};

    uint8_t tmp[64] __attribute__((aligned(32))) = {0};
    uint8_t *plaintext_le_unaligned = (uint8_t *)(((uintptr_t)&plaintext_le[0]) + 19);
    int32_t result = 0;

    result = hca_aes_setkey(&scl, SCL_AES_KEY128, key128, SCL_ENCRYPT);
    TEST_ASSERT_TRUE(SCL_OK == result);

    /* F.1.1 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_LITTLE_ENDIAN_MODE, plaintext_le_unaligned,
                                     64, tmp, NULL);
    TEST_ASSERT_TRUE(SCL_OK == result);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_le, tmp, sizeof(ciphertext_le));
    memset(tmp, 0, sizeof(tmp));
    /* Setup a timeout just in case */
    set_timeout(TIMEOUT);

    /* F.1.2 ECB-AES128.Encrypt */
    result = hca_aes_cipher_with_dma(&scl, SCL_AES_ECB, SCL_ENCRYPT, 
                                     SCL_LITTLE_ENDIAN_MODE, plaintext_le_unaligned,
                                     64, tmp, finish_callback);
    TEST_ASSERT_TRUE(SCL_OK == result);
    while (0 == unlock);
    TEST_ASSERT_TRUE(SCL_OK == status);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_le, tmp, sizeof(ciphertext_le));
}
#endif
