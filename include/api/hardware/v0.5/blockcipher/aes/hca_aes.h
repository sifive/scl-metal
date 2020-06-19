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
 * @file hca_aes.h
 * @brief hardware aes implementation/wrapper
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _HCA_AES_H
#define _HCA_AES_H

#include <stddef.h>
#include <stdint.h>

#include <crypto_cfg.h>

#include <api/defs.h>
#include <api/scl_api.h>

#include <scl/scl_retdefs.h>

/**
 * \addtogroup HCA
 * \addtogroup HCA_API_AES
 * \ingroup HCA
 *  @{
 */

CRYPTO_FUNCTION int32_t hca_aes_setkey(const metal_scl_t *const scl,
                                       scl_aes_key_type_t type, uint64_t *key,
                                       scl_process_t aes_process);

CRYPTO_FUNCTION int32_t hca_aes_setiv(const metal_scl_t *const scl,
                                      uint64_t *initvec);

CRYPTO_FUNCTION int32_t hca_aes_cipher(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                       scl_process_t aes_process, scl_endianness_t data_endianness, 
                       const uint8_t *const data_in, size_t data_len, uint8_t *data_out);

CRYPTO_FUNCTION int32_t hca_aes_auth(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                     scl_process_t aes_process,
                     scl_endianness_t data_endianness, uint32_t auth_option,
                     const uint8_t *const aad, size_t aad_len, 
                     const uint8_t *const data_in, size_t data_len, uint8_t *data_out, uint64_t *tag);

/** @}*/

#endif /* _HCA_AES_H */