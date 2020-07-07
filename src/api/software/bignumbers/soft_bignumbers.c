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
 * @file soft_bignumbers.c
 * @brief arithmetic on bignumber, software implementation
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <api/macro.h>
#include <api/utils.h>

#include <scl/scl_retdefs.h>

#include <string.h>

#include <api/software/bignumbers/soft_bignumbers.h>

int32_t soft_bignum_compare(const uint64_t *const a, const uint64_t *const b,
                            size_t word_size)
{
    size_t i;

    i = word_size;

    /* If word_size == 0 then the array are considered equals */
    while (i != 0)
    {
        i--;
        if (a[i] > b[i])
        {
            return (1);
        }
        if (a[i] < b[i])
        {
            return (-1);
        }
    }
    return (0);
}

uint64_t soft_bignum_inc(uint64_t *const array,
                                                size_t nb_32b_words)
{
    size_t i = 0;
    uint64_t carry = 1;
    register uint64_t previous = 0;

    if(0 == nb_32b_words) {
        return(0);
    }

    for (i = 0; i < nb_32b_words / 2; i++) {
        previous = array[i];
        array[i] += carry;
        carry = array[i] < previous ? 1: 0;
    }

    if (nb_32b_words % 2) {
        previous = *((uint32_t *)&array[i]);
        *((uint32_t *)&array[i]) += carry;
        carry = *((uint32_t *)&array[i]) < previous ? 1: 0;
    }

    return(carry);
}

uint64_t soft_bignum_add(const uint64_t *const in_a,
                        const uint64_t *const in_b,
                        uint64_t *const out,
                        size_t nb_32b_words)
{
    size_t i = 0;
    uint64_t carry = 0;
    register uint64_t previous = 0;

    if(0 == nb_32b_words) {
        return(0);
    }

    for (i = 0; i < nb_32b_words / 2; i++) {
        previous = in_a[i];
        out[i] = in_a[i] + in_b[i];
        out[i] += carry;
        carry = out[i] < previous ? 1: 0;
    }

    if (nb_32b_words % 2) {
        previous = *((uint32_t *)&in_a[i]);
        *((uint32_t *)&out[i]) = *((uint32_t *)&in_a[i]) + *((uint32_t *)&in_b[i]);
        *((uint32_t *)&out[i]) += carry;
        carry = *((uint32_t *)&out[i]) < previous ? 1: 0;
    }

    return(carry);
}

uint64_t soft_bignum_sub(const uint64_t *const in_a,
                                                const uint64_t *const in_b,
                                                uint64_t *const out,
                                                size_t nb_32b_words)
{
    size_t i = 0;
    uint64_t carry = 0;
    register uint64_t previous = 0;

    if(0 == nb_32b_words) {
        return(0);
    }

    for (i = 0; i < nb_32b_words / 2; i++) {
        previous = in_a[i];
        out[i] = in_a[i] - carry;
        carry = out[i] > previous ? 1: 0;

        previous = out[i];
        out[i] = out[i]  - in_b[i];
        carry |= out[i] > previous ? 1: 0;
    }

    if (nb_32b_words % 2) {
        previous = *((uint32_t *)&in_a[i]);
        *((uint32_t *)&out[i]) = *((uint32_t *)&in_a[i]) - carry;
        carry = *((uint32_t *)&out[i]) > previous ? 1: 0;

        previous = *((uint32_t *)&out[i]);
        *((uint32_t *)&out[i]) = *((uint32_t *)&out[i])  - *((uint32_t *)&in_b[i]);
        carry |= *((uint32_t *)&out[i]) > previous ? 1: 0;
    }
 
    return(carry);
}

void soft_bignum_mult(const uint64_t *const in_a, const uint64_t *const in_b,
                      uint64_t *const out, size_t nb_32b_words)
{
    size_t i, j;
    uint32_t carry;
    uint64_t ab;

    const uint32_t *a = (const uint32_t *)in_a;
    const uint32_t *b = (const uint32_t *)in_b;

    uint32_t *res = (uint32_t *)out;

    /**
     * carefull here, nb_32b_words is 2 * the number of 64 bits words of inputs
     */
    memset(out, 0, nb_32b_words * 2 * sizeof(uint32_t));

    // 1.
    for (i = 0; i < nb_32b_words; i++)
    {
        for (carry = 0, j = 0; j < nb_32b_words; j++)
        {
            ab = (uint64_t)b[i] * (uint64_t)a[j];

            res[i + j] = res[i + j] + carry;
            if (res[i + j] < carry)
            {
                carry = 1;
            }
            else
            {
                carry = 0;
            }

            res[i + j] += (ab & UINT32_MAX);
            if (res[i + j] < (ab & UINT32_MAX))
            {
                carry++;
            }

            /* load 32 bits msb into carry */
            carry += (ab >> (sizeof(uint32_t) * __CHAR_BIT__));
        }
        res[i + nb_32b_words] += carry;
    }
}

int32_t soft_bignum_leftshift(const metal_scl_t *const scl,
                              const uint64_t *const in, uint64_t *const out,
                              size_t shift, size_t nb_32b_words)
{
    size_t revshift, bit_shift_div64, bit_shift_mod64;
    size_t i;
    (void)scl;

    if ((NULL == in) || (NULL == out))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((0 == nb_32b_words) ||
        (shift >= nb_32b_words * sizeof(uint32_t) * __CHAR_BIT__))
    {
        return (SCL_INVALID_LENGTH);
    }

    bit_shift_div64 = shift / (sizeof(uint64_t) * __CHAR_BIT__);
    bit_shift_mod64 = shift & ((sizeof(uint64_t) * __CHAR_BIT__) - 1);

    i = nb_32b_words / 2;

    revshift = (sizeof(uint64_t) * __CHAR_BIT__) - bit_shift_mod64;

    if (0 != nb_32b_words % 2)
    {
        *((uint32_t *)&out[i]) = *((uint32_t *)&in[i - bit_shift_div64])
                                 << bit_shift_mod64;

        if (i > bit_shift_div64 + 1)
        {
            *((uint32_t *)&out[i]) |=
                *((uint32_t *)&in[i - bit_shift_div64 - 1]) >> revshift;
        }
    }

    while (i > bit_shift_div64 + 1)
    {
        i--;
        out[i] = in[i - bit_shift_div64] << bit_shift_mod64;
        out[i] |= in[-bit_shift_div64 - 1] >> revshift;
    }

    if (i > bit_shift_div64)
    {
        i--;
        out[i] = in[i - bit_shift_div64] << bit_shift_mod64;
    }

    memset(out, 0, shift / __CHAR_BIT__);

    return (SCL_OK);
}

int32_t soft_bignum_rightshift(const metal_scl_t *const scl,
                               const uint64_t *const in, uint64_t *const out,
                               size_t shift, size_t nb_32b_words)
{
    size_t revshift, bit_shift_div64, bit_shift_mod64;
    size_t i;
    (void)scl;

    uint32_t *out_32b = (uint32_t *)out;

    if ((NULL == in) || (NULL == out))
    {
        return (SCL_INVALID_INPUT);
    }

    if ((0 == nb_32b_words) ||
        (shift >= nb_32b_words * sizeof(uint32_t) * __CHAR_BIT__))
    {
        return (SCL_INVALID_LENGTH);
    }

    bit_shift_div64 = shift / (sizeof(uint64_t) * __CHAR_BIT__);
    bit_shift_mod64 = shift & ((sizeof(uint64_t) * __CHAR_BIT__) - 1);

    i = 0;

    revshift = (sizeof(uint64_t) * __CHAR_BIT__) - bit_shift_mod64;

    while (i + bit_shift_div64 + 1 < nb_32b_words / 2)
    {
        out[i] = in[i + bit_shift_div64] >> bit_shift_mod64;
        out[i] |= in[i + bit_shift_div64 + 1] << revshift;
        i++;
    }

    if (i + bit_shift_div64 < nb_32b_words / 2)
    {
        out[i] = in[i + bit_shift_div64] >> bit_shift_mod64;
        if (0 != nb_32b_words % 2)
        {
            out[i] |= (uint64_t)(*((uint32_t *)&in[i + bit_shift_div64 + 1]))
                      << revshift;
            i++;
        }
    }

    if (0 != nb_32b_words % 2)
    {
        *((uint32_t *)&out[i]) =
            *((uint32_t *)&in[i + bit_shift_div64]) >> bit_shift_mod64;
    }

    memset((void *)((uint8_t *)&out_32b[nb_32b_words] -
                    (uint8_t *)(shift / __CHAR_BIT__)),
           0, shift / __CHAR_BIT__);

    return (SCL_OK);
}
