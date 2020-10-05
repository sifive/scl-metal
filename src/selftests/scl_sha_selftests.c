/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 ******************************************************************************/

/**
 * @file scl_sha2_selftests.c
 * @brief Self tests for sha2
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <scl/scl_selftests.h>

#include <scl/scl_retdefs.h>
#include <scl/scl_sha.h>

#include <string.h>

int32_t scl_hash_sha256_selftest(const metal_scl_t *const scl)
{
    int32_t result = 0;

    /* abc */
    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA256_BYTE_HASHSIZE];
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA256_BYTE_HASHSIZE] = {
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40,
        0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17,
        0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};

    result = scl_sha(scl, SCL_HASH_SHA256, message, sizeof(message), digest,
                     &digest_len);

    if (SCL_OK != result)
    {
        return (result);
    }
    else if ((SHA256_BYTE_HASHSIZE != digest_len) ||
             (0 != memcmp(expected_digest, digest, sizeof(expected_digest))))
    {
        return (SCL_ERROR);
    }

    return (SCL_OK);
}

int32_t scl_hash_sha384_selftest(const metal_scl_t *const scl)
{
    int32_t result = 0;

    /* abc */
    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA384_BYTE_HASHSIZE];
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA384_BYTE_HASHSIZE] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
        0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
        0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};

    result = scl_sha(scl, SCL_HASH_SHA384, message, sizeof(message), digest,
                     &digest_len);

    if (SCL_OK != result)
    {
        return (result);
    }
    else if ((SHA384_BYTE_HASHSIZE != digest_len) ||
             (0 != memcmp(expected_digest, digest, sizeof(expected_digest))))
    {
        return (SCL_ERROR);
    }

    return (SCL_OK);
}

int32_t scl_hash_sha512_selftest(const metal_scl_t *const scl)
{
    int32_t result = 0;

    /* abc */
    static const uint8_t message[] = {
        0x61,
        0x62,
        0x63,
    };

    uint8_t digest[SHA512_BYTE_HASHSIZE];
    size_t digest_len = sizeof(digest);

    static const uint8_t expected_digest[SHA512_BYTE_HASHSIZE] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
        0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
        0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
        0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
        0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
        0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};

    result = scl_sha(scl, SCL_HASH_SHA512, message, sizeof(message), digest,
                     &digest_len);

    if (SCL_OK != result)
    {
        return (result);
    }
    else if ((SHA512_BYTE_HASHSIZE != digest_len) ||
             (0 != memcmp(expected_digest, digest, sizeof(expected_digest))))
    {
        return (SCL_ERROR);
    }

    return (SCL_OK);
}
