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
 * @file scl_aes_cbc.h
 * @brief defines the AES for the CBC mode.
 * AES is NIST FIPS-197
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _SCL_AES_CBC_H
#define _SCL_AES_CBC_H

#include <stdint.h>
#include <stdio.h>

#include <scl_cfg.h>

/**
 * \addtogroup SCL
 * \addtogroup SCL_AES
 * \ingroup SCL
 *  @{
 */

    SCL_FUNCTION int32_t scl_aes_cbc_init(const metal_scl_t *const scl_ctx,
                                          const uint8_t *const key,
                                          const size_t key_byte_len,
                                          const uint8_t *const iv,
                                          const size_t iv_byte_len,
                                          scl_process_t mode);
    SCL_FUNCTION int32_t scl_aes_cbc_core(const metal_scl_t *const scl_ctx,
                                          uint8_t *dst, uint8_t *src,
                                          size_t src_byte_len,
                                          scl_process_t mode);
    SCL_FUNCTION int32_t scl_aes_cbc(const metal_scl_t *const scl_ctx, uint8_t *dst, uint8_t *src,
                size_t src_byte_len, const uint8_t *const key,
                const size_t key_byte_len, const uint8_t *const iv,
                const size_t iv_byte_len, scl_process_t mode);

/** @}*/

#endif /* _SCL_AES_ECB_H */
