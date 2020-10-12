/**
 * @file test_scl_ecdsa_runner.c
 * @brief test runner for test_scl_ecdsa.c
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(scl_ecdsa)
{
    /* Verification */

    /* SECP256r1 */
    RUN_TEST_CASE(scl_ecdsa, test_p256r1_curve_input_256B_verif_success);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p256r1_curve_input_256B_verif_invalid_signature);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p256r1_curve_input_256B_verif_invalid_signature_zero);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p256r1_curve_input_256B_verif_invalid_signature_curve_p);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p256r1_curve_input_256B_verif_invalid_signature_curve_n);

    /* SECP384r1 */
    RUN_TEST_CASE(scl_ecdsa, test_p384r1_curve_input_384B_verif_success);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p384r1_curve_input_384B_verif_invalid_signature);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p384r1_curve_input_384B_verif_invalid_signature_zero);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p384r1_curve_input_384B_verif_invalid_signature_curve_p);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p384r1_curve_input_384B_verif_invalid_signature_curve_n);

    /* SECP521r1 */
    RUN_TEST_CASE(scl_ecdsa, test_p521r1_curve_input_512B_verif_success);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p521r1_curve_input_512B_verif_invalid_signature);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p521r1_curve_input_512B_verif_invalid_signature_zero);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p521r1_curve_input_512B_verif_invalid_signature_curve_p);
    RUN_TEST_CASE(scl_ecdsa,
                  test_p521r1_curve_input_512B_verif_invalid_signature_curve_n);

    /* Signature */

    /* SECP256r1 */
    RUN_TEST_CASE(scl_ecdsa, test_p256r1_curve_input_256B_sign);
    RUN_TEST_CASE(scl_ecdsa, test_p256r1_curve_input_216B_sign);
    RUN_TEST_CASE(scl_ecdsa, test_p256r1_curve_input_264B_sign);

    /* SECP384r1 */
    RUN_TEST_CASE(scl_ecdsa, test_p384r1_curve_input_384B_sign);
    RUN_TEST_CASE(scl_ecdsa, test_p384r1_curve_input_216B_sign);
    RUN_TEST_CASE(scl_ecdsa, test_p384r1_curve_input_385B_sign);

    /* SECP521r1 */
    RUN_TEST_CASE(scl_ecdsa, test_p521r1_curve_input_512B_sign);
    RUN_TEST_CASE(scl_ecdsa, test_p521r1_curve_input_216B_sign);
}
