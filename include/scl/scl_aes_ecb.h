/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_aes_ecb.h
 * @brief defines the AES for the ECB mode.
 * AES is NIST FIPS-197, ECB is SP800-38A
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

#ifndef _SCL_AES_ECB_H
#define _SCL_AES_ECB_H

#include <stdint.h>
#include <stdio.h>

#include <scl_cfg.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

    /** \addtogroup SCL_API
     *  @{
     */
    
    SCL_FUNCTION int32_t scl_aes_ecb_init(const metal_scl_t *const scl_ctx, const uint8_t *const key, const size_t key_byte_len, scl_process_t mode);
    SCL_FUNCTION int32_t scl_aes_ecb_core(const metal_scl_t *const scl_ctx, uint8_t *dst, uint8_t *src, size_t src_byte_len, scl_process_t mode);
    SCL_FUNCTION int32_t scl_aes_ecb(const metal_scl_t *const scl_ctx, uint8_t *dst, uint8_t *src, size_t src_byte_len, const uint8_t *const key, const size_t key_byte_len, scl_process_t mode);

    /** @}*/

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _SCL_AES_ECB_H */
