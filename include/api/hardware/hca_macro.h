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
 * @file hca_macro.h
 * @brief macro definition specific to hca
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _HCA_MACRO_H
#define _HCA_MACRO_H

#include <metal/io.h>

#include <api/scl_api.h>

/** 
 * \addtogroup HCA
 * \addtogroup HCA_MACRO
 * \ingroup HCA
 *  @{
 */

#define METAL_REG64(base, offset)                                              \
    (__METAL_ACCESS_ONCE((uint64_t *)((base) + (offset))))
#define METAL_REG32(base, offset)                                              \
    (__METAL_ACCESS_ONCE((uint32_t *)((base) + (offset))))

static __inline__ void hca_setfield32(const metal_scl_t *const scl,
                                      uint32_t reg, uint32_t value, char offset,
                                      uint32_t mask)
{
    METAL_REG32(scl->hca_base, reg) &= ~(mask << offset);
    METAL_REG32(scl->hca_base, reg) |= ((value & mask) << offset);
}

#define GET_UNIT32(data, k)                                                    \
    ((*(data + k + 3) << 24) + (*(data + k + 2) << 16) +                       \
     (*(data + k + 1) << 8) + (*(data + k)))
#define GET_UNIT64(data, k)                                                    \
    ((((uint64_t)GET_UNIT32(data, (k + 4))) << 32) +                           \
     (uint64_t)GET_UNIT32(data, k))

/** @}*/

#endif
