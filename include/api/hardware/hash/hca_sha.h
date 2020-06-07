/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file hca_sha.h
 * @brief hardware sha implementation/wrapper
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

#ifndef _HCA_SHA_H
#define _HCA_SHA_H

#include <stddef.h>
#include <stdint.h>

#include <crypto_cfg.h>

#include <api/defs.h>
#include <api/scl_api.h>

#include <api/hardware/hca_macro.h>

#include <scl/scl_retdefs.h>

CRYPTO_FUNCTION int32_t sha_init_hca(metal_scl_t *const scl,
                                     sha_ctx_t *const ctx,
                                     hash_mode_t hash_mode,
                                     endianness_t data_endianness);

CRYPTO_FUNCTION int32_t sha_core_hca(metal_scl_t *const scl,
                                     sha_ctx_t *const ctx,
                                     const uint8_t *const data,
                                     size_t data_byte_len);

CRYPTO_FUNCTION int32_t sha_finish_hca(metal_scl_t *const scl,
                                       sha_ctx_t *const ctx,
                                       uint8_t *const hash,
                                       size_t *const hash_len);

CRYPTO_FUNCTION int32_t sha_block_hca(metal_scl_t *const scl,
                                      hash_mode_t hash_mode,
                                      uint32_t NbBlocks512,
                                      const uint8_t *const data_in);

CRYPTO_FUNCTION int32_t sha_read_hca(metal_scl_t *const scl,
                                     hash_mode_t hash_mode,
                                     uint8_t *const data_out);

#endif /* _HCA_SHA_H */