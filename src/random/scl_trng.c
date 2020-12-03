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
 * @file scl_trng.c
 * @brief implementation of the True Random Number Generator generic high level 
 * interface
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <scl/scl_retdefs.h>
#include <scl/scl_trng.h>

#include <backend/api/scl_backend_api.h>

int32_t scl_trng_init(const metal_scl_t *const scl)
{
    int32_t result;

    if (NULL == scl)
    {
        return (SCL_INVALID_INPUT);
    }

    if (NULL == scl->trng_func.init)
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    result = scl->trng_func.init(scl);
    if (SCL_OK != result)
    {
        return (result);
    }

    return (SCL_OK);
}

int32_t scl_trng_get_data(const metal_scl_t *const scl,  uint32_t *data_out)
{
    int32_t result;

    if (NULL == scl)
    {
        return (SCL_INVALID_INPUT);
    }

    if (NULL == scl->trng_func.get_data)
    {
        return (SCL_ERROR_API_ENTRY_POINT);
    }

    result = scl->trng_func.get_data(scl, data_out);
    if (SCL_OK != result)
    {
        return (result);
    }

    return (SCL_OK);
}
