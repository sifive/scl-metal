/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * Copyright 2020 SiFive, Inc
 * SPDX-License-Identifier: MIT
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
 * @file scl_trng.h
 * @brief scl TRNG (True Random Number Generator) functions
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#ifndef SCL_TRNG_H
#define SCL_TRNG_H

#include <stdint.h>

#include <backend/api/scl_backend_api.h>
#include <scl_cfg.h>

/**
 * @addtogroup SCL
 * @addtogroup SCL_TRNG
 * @ingroup SCL
 *  @{
 */

/**
 * @brief Initialize TRNG
 *
 * @param[in] scl               metal scl context
 * @return 0                    SUCCESS
 * @return != 0                 otherwise @ref scl_errors_t
 */
SCL_FUNCTION int32_t scl_trng_init(const metal_scl_t *const scl);

/**
 * @brief get 32bits random value
 *
 * @param[in] scl               metal scl context
 * @param[out] output           output buffer
 * @param[in] output_len        output length
 * @return 0                    SUCCESS
 * @return != 0                 otherwise @ref scl_errors_t
 */
SCL_FUNCTION int32_t scl_trng_get_data(const metal_scl_t *const scl,
                                       uint8_t *const output,
                                       size_t output_len);

/** @}*/

#endif /* SCL_TRNG_H */
