/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_sha.h
 * @brief defines the generic hash function interface, where the hash function
 * is transmitted as a parameter.
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

#ifndef _SCL_SHA_H
#define _SCL_SHA_H

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include <stddef.h>
#include <stdint.h>

#include <scl_cfg.h>

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

#include <api/hash/sha.h>
#include <api/scl_api.h>

    typedef sha_ctx_t scl_sha_ctx_t;

    SCL_FUNCTION int32_t scl_sha(const metal_scl_t *const scl_ctx, 
                                 scl_hash_mode_t algo,
                                 const uint8_t *const data,
                                 size_t data_byte_len, uint8_t *const hash,
                                 size_t *const hash_len);
    SCL_FUNCTION int32_t scl_sha_init(const metal_scl_t *const scl_ctx, 
                                      scl_sha_ctx_t *const ctx,
                                      scl_hash_mode_t algo);
    SCL_FUNCTION int32_t scl_sha_core(const metal_scl_t *const scl_ctx, 
                                      scl_sha_ctx_t *const ctx,
                                      const uint8_t *const data,
                                      size_t data_len);
    SCL_FUNCTION int32_t scl_sha_finish(const metal_scl_t *const scl_ctx, 
                                        scl_sha_ctx_t *const ctx,
                                        uint8_t *const hash,
                                        size_t *const hash_len);
    SCL_FUNCTION int32_t scl_valid_hash_digest_length(size_t inputlength);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SCL_SHA_H */
