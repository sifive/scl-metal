/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file scl_init.c
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

#include <stdint.h>
#include <stdio.h>

#include <api/scl_api.h>
#include <scl_cfg.h>

#include <scl/scl_utils.h>

#define UINT32(data)                                                           \
    ((*(data + 3) << 24) + (*(data + 2) << 16) + (*(data + 1) << 8) + (*(data)))
#define UINT64(data)                                                           \
    (((uint64_t)UINT32(data + 4) << 32) + (uint64_t)UINT32(data))

SCL_DATA metal_scl_t *scl_ctx = NULL;

int scl_format_key(const uint8_t *const key, const size_t key_byte_len,
                                uint64_t *key_formated)
{
    if (NULL == key)
    {
        return SCL_INVALID_INPUT;
    }
    if ((SCL_KEY128 != key_byte_len) && (SCL_KEY192 != key_byte_len) &&
        (SCL_KEY256 != key_byte_len))
    {
        return SCL_INVALID_INPUT;
    }

    if (SCL_KEY256 == key_byte_len)
    {
        key_formated[4] = UINT64(&key[24]);
    }
    else
    {
        key_formated[4] = 0;
    }
    if (SCL_KEY192 >= key_byte_len)
    {
        key_formated[3] = UINT64(&key[16]);
    }
    else
    {
        key_formated[3] = 0;
    }
    key_formated[1] = UINT64(&key[8]);
    key_formated[0] = UINT64(&key[0]);
}