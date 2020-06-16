/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file utils.c
 * @brief
 * @version 0.1
 * @date 2020-06-03
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

#include <api/utils.h>
#include <scl/scl_retdefs.h>

int32_t copy_u8_2_u32_be(uint32_t *const dest, const uint8_t *const src,
                         size_t len)
{
    size_t i;

    if ((NULL == dest) || (NULL == src))
    {
        return (SCL_ERROR);
    }

    if ((len % sizeof(uint32_t)) != 0)
    {
        return (SCL_ERROR);
    }

    i = 0;
    while (i < len)
    {
        dest[i >> 2] = ((uint32_t)src[i] << 24) ^ ((uint32_t)src[i + 1] << 16) ^
                       ((uint32_t)src[i + 2] << 8) ^ ((uint32_t)src[i + 3]);

        i += sizeof(uint32_t);
    }

    return (SCL_OK);
}

int32_t copy_u8_2_u64_be(uint64_t *const dest, const uint8_t *const src,
                         size_t len)
{
    size_t i;

    if ((NULL == dest) || (NULL == src))
    {
        return (SCL_ERROR);
    }

    if ((len % sizeof(uint64_t)) != 0)
    {
        return (SCL_ERROR);
    }

    i = 0;
    while (i < len)
    {
        dest[i >> 3] =
            ((uint64_t)src[i] << 56) ^ ((uint64_t)src[i + 1] << 48) ^
            ((uint64_t)src[i + 2] << 40) ^ ((uint64_t)src[i + 3] << 32) ^
            ((uint64_t)src[i + 4] << 24) ^ ((uint64_t)src[i + 5] << 16) ^
            ((uint64_t)src[i + 6] << 8) ^ ((uint64_t)src[i + 7]);

        i += sizeof(uint64_t);
    }

    return (SCL_OK);
}

int32_t copy_u32_2_u8_be(uint8_t *const dest, const uint32_t *const src,
                         size_t len)
{
    size_t i, index;
    size_t stop;

    if ((len % sizeof(uint32_t)) != 0)
    {
        return (SCL_ERROR);
    }

    stop = len >> 2;

    for (i = 0; i < stop; i++)
    {
        index = i << 2;
        dest[index] = (uint8_t)(src[i] >> 24);
        dest[index + 1] = (uint8_t)(src[i] >> 16);
        dest[index + 2] = (uint8_t)(src[i] >> 8);
        dest[index + 3] = (uint8_t)(src[i]);
    }

    return (SCL_OK);
}

int32_t copy_u64_2_u8_be(uint8_t *const dest, const uint64_t *const src,
                         size_t len)
{
    size_t i, index;
    size_t stop;

    if ((len % sizeof(uint64_t)) != 0)
    {
        return (SCL_ERROR);
    }

    stop = len >> 3;

    for (i = 0; i < stop; i++)
    {
        index = i << 3;
        dest[index] = (uint8_t)(src[i] >> 56);
        dest[index + 1] = (uint8_t)(src[i] >> 48);
        dest[index + 2] = (uint8_t)(src[i] >> 40);
        dest[index + 3] = (uint8_t)(src[i] >> 32);
        dest[index + 4] = (uint8_t)(src[i] >> 24);
        dest[index + 5] = (uint8_t)(src[i] >> 16);
        dest[index + 6] = (uint8_t)(src[i] >> 8);
        dest[index + 7] = (uint8_t)(src[i]);
    }

    return (SCL_OK);
}

int32_t copy_n_u8_2_m_u64_be(uint64_t *const dest, size_t len_dest, const uint8_t *const src, size_t len_src)
{
    size_t i, j, k;

    if ((NULL == dest) || (NULL == src))
    {
        return (SCL_ERROR);
    }

    for (k=0; k < len_dest; k++)
    {
        dest[k] = 0;
    }

    i = ((len_src >> 3) + (len_src & 7)?1:0);
    if ( ((len_src >> 3) + (len_src & 7)?1:0) > len_dest )
    {
        return (SCL_ERROR);
    }

    k = 0;
    i = len_src;
    while (i >> 3)
    {
        dest[len_dest - 1 - k] = 
            ((uint64_t)src[i - 8] << 56) ^ ((uint64_t)src[i - 7] << 48) ^
            ((uint64_t)src[i - 6] << 40) ^ ((uint64_t)src[i - 5] << 32) ^
            ((uint64_t)src[i - 4] << 24) ^ ((uint64_t)src[i - 3] << 16) ^
            ((uint64_t)src[i - 2] <<  8) ^ ((uint64_t)src[i - 1]);
        i -= sizeof(uint64_t);
        k++;
    }

    j = 0;
    while (i)
    {
        dest[len_dest - 1 - k] = (dest[len_dest - 1 - k] << 8) ^ (uint64_t)src[j];
        j++;
        i--;
    }

    return (SCL_OK);
}