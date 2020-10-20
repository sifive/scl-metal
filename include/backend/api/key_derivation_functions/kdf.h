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
 * @file sha.h
 * @brief sha implementation/wrapper
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_BACKEND_KDF_H
#define SCL_BACKEND_KDF_H

#include <backend/api/hash/sha/sha.h>

/**
 * @addtogroup COMMON
 * @addtogroup KDF
 * @ingroup COMMON
 *  @{
 */

/*! @brief Unified x9.63 kdf context */
typedef struct
{
    /*! @brief shared info buffer */
    const uint8_t *shared_info;
    /*! @brief shared info length (in byte) */
    size_t shared_info_len;
    /**
     * @brief sha context
     * @note we use pointer here, in order to avoid sha context duplication
     */
    sha_ctx_t *sha_ctx;
    /*! @brief Hash mode */
    hash_mode_t hash_mode;
} x963kdf_ctx_t;

/** @}*/

#endif /* SCL_BACKEND_KDF_H */
