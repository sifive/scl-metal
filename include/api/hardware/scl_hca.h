/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_hca.h
 * @brief 
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
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

#ifndef _SCL_HCA_H
#define _SCL_HCA_H

#include <stdint.h>
#include <stdio.h>

#include <api/scl_api.h>
#include <crypto_cfg.h>

#define HCA_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)
#include <api/hardware/sifive_hca-0.5.x.h>
#endif

typedef enum
{
    SCL_HCA_AES_MODE = 0,
    SCL_HCA_SHA_MODE = 1
} scl_hca_mode_t;

/**
 * @brief load AES key into Hardware Crypto Accelerator
 *
 * @param[in] scl       Structure than contain HCA information
 * @param[in] type      Type of key (AES128 key, AES192 key, ...)
 * @param[in] key       key to load
 * @return int  0 in case of success
 * @return int  !=0 otherwise (see scl_retdefs.h to have more detailed)
 */
int scl_hca_aes_setkey(metal_scl_t *scl, scl_aes_key_type_t type,
                       uint64_t *key) CRYPTO_FUNCTION;

int scl_hca_aes_setiv(metal_scl_t *scl, uint64_t *initvec) CRYPTO_FUNCTION;

int scl_hca_aes_cipher(metal_scl_t *scl, scl_aes_mode_t aes_mode,
                       scl_process_t aes_process,
                       scl_endianness_t data_endianness, uint32_t NbBlocks128,
                       uint8_t *data_in, uint8_t *data_out) CRYPTO_FUNCTION;

int scl_hca_aes_auth(metal_scl_t *scl, scl_aes_mode_t aes_mode,
                     scl_process_t aes_process,
                     scl_endianness_t data_endianness, uint32_t auth_option,
                     uint64_t aad_len, uint8_t *aad, uint64_t data_len,
                     uint8_t *data_in, uint8_t *data_out,
                     uint64_t *tag) CRYPTO_FUNCTION;

int scl_hca_trng_init(metal_scl_t *scl) CRYPTO_FUNCTION;

int scl_hca_trng_getdata(metal_scl_t *scl, uint32_t *data_out) CRYPTO_FUNCTION;

#endif