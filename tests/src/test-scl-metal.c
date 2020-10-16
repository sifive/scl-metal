/**
 * @file test-scl-metal.c
 * @brief Main of the scl-metal tests
 * @details This run all test group
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity_fixture.h"

#include <stdint.h>
#include <stdlib.h>

#include <backend/hardware/scl_hca.h>
#include <metal/machine/platform.h>

#if UINT32_MAX == UINTPTR_MAX
#define STACK_CHK_GUARD 0xe2dee396
#else
#define STACK_CHK_GUARD 0x595e9fbd94fda766
#endif

extern uintptr_t __stack_chk_guard;
uintptr_t __stack_chk_guard = STACK_CHK_GUARD;

void __stack_chk_fail(void);
void __stack_chk_fail(void) { TEST_FAIL_MESSAGE("Stack smashing detected"); }

static void RunAllTests(void)
{
    UnityFixture.Verbose = 1;

    // soft implementation
    RUN_TEST_GROUP(soft_sha_224);
    RUN_TEST_GROUP(soft_sha_256);
    RUN_TEST_GROUP(soft_sha_384);
    RUN_TEST_GROUP(soft_sha_512);

    // scl api implementation
    RUN_TEST_GROUP(scl_soft_sha_224);
    RUN_TEST_GROUP(scl_soft_sha_256);
    RUN_TEST_GROUP(scl_soft_sha_384);
    RUN_TEST_GROUP(scl_soft_sha_512);

    /* HMAC */
    RUN_TEST_GROUP(soft_hmac);

    /* utils */
    RUN_TEST_GROUP(utils);

    // software bignumbers
    RUN_TEST_GROUP(soft_bignumbers);

    /* ECC */
    RUN_TEST_GROUP(soft_ecc);
    RUN_TEST_GROUP(soft_ecc_keygen);
    RUN_TEST_GROUP(scl_ecc_keygen);

    /* ECDSA */
    RUN_TEST_GROUP(soft_ecdsa);
    RUN_TEST_GROUP(scl_ecdsa);

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)
    // hardware implementation
    RUN_TEST_GROUP(hca_sha_224);
    RUN_TEST_GROUP(hca_sha_256);
    RUN_TEST_GROUP(hca_sha_384);
    RUN_TEST_GROUP(hca_sha_512);

    // hardware implementation
    RUN_TEST_GROUP(hca_aes_128);
    RUN_TEST_GROUP(hca_aes_192);
    RUN_TEST_GROUP(hca_aes_256);

    // scl api implementation
    RUN_TEST_GROUP(scl_aes_128);
    RUN_TEST_GROUP(scl_aes_192);
    RUN_TEST_GROUP(scl_aes_256);
#endif
}

int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTests);
}
