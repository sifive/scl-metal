/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file hca_aes.h
 * @brief hardware aes implementation/wrapper
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

#ifndef _HCA_AES_H
#define _HCA_AES_H

#include <stddef.h>
#include <stdint.h>

#include <crypto_cfg.h>

#include <api/defs.h>
#include <api/scl_api.h>

#include <scl/scl_retdefs.h>

CRYPTO_FUNCTION int32_t hca_aes_setkey(const metal_scl_t *const scl, scl_aes_key_type_t type, uint64_t *key);

CRYPTO_FUNCTION int32_t hca_aes_setiv(metal_scl_t *scl, uint64_t *initvec);

CRYPTO_FUNCTION int32_t hca_aes_cipher(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                       scl_process_t aes_process,
                       scl_endianness_t data_endianness, uint32_t NbBlocks128,
                       uint8_t *data_in, uint8_t *data_out);

CRYPTO_FUNCTION int32_t hca_aes_auth(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                     scl_process_t aes_process,
                     scl_endianness_t data_endianness, uint32_t auth_option,
                     uint64_t aad_len, uint8_t *aad, uint64_t data_len,
                     uint8_t *data_in, uint8_t *data_out, uint64_t *tag);

#endif /* _HCA_AES_H */