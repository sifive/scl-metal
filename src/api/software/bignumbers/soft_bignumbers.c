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

__attribute__((naked)) uint64_t soft_bignum_inc(const uint64_t *const array,
                                                size_t nb_32b_words)
{
    /* just to clear warnings */
    (void)array;
    (void)nb_32b_words;

    /**
     * just as a reminder:
     * array => a0 register
     * nb_32b_words => a1 register
     */

#if __riscv_xlen == 32
    __asm__ __volatile__(
        /* init carry to 0 */
        "mv a5, zero \n"

        /* check word_size is >0 and < 0x3FFFFFFF*/
        "li t1, 0x3FFFFFFF \n"
        "beqz a1, 2f\n"
        "bgtu a1, t1, 2f\n"

        /* stop condition */
        "slli a1, a1, 2 \n"
        "add a1, a0, a1 \n"

        /* init t2 */
        "li t2, 1 \n"

        /* start loop */
        "1: \n"
        /*  load values */
        "   lw t1, 0(a0) \n"

        /*  add elements */
        /*  in_a[i] + in_b[i] */
        "   add t0, t1, t2 \n"
        /*  add carry */
        "   add t0, t0, a5 \n"
        /*  if res <  in_a[i] */
        "   sltu a5, t0, t1 \n"

        /*  store 32 bits result */
        "   sw t0, 0(a0) \n"

        /*  update pointer addr */
        "   addi a0, a0, 4 \n"

        /*  set t2 to 0 */
        "   mv t2, zero \n"

        "   bltu a0, a1, 1b \n"

        /* return carry (a5) */
        "2: \n"
        "   mv a0, a5 \n"
        "   mv a1, zero \n"
        "   ret \n" ::
            :);
#elif __riscv_xlen == 64
    __asm__ __volatile__(
        /* init carry to 0 */
        "mv a5, zero \n"

        /* check word_size is >0 and < 0x3FFFFFFF*/
        "li t1, 0x3FFFFFFF \n"
        "beqz a1, 3f\n"
        "bgtu a1, t1, 3f\n"

        /* stop condition */
        "slli a1, a1, 2 \n"
        "add a1, a0, a1 \n"

        /* init t2 */
        "li t2, 1 \n"

        /* case there is only one 32bit word */
        "addi a4, a0, 4 \n"
        "beq a1, a4, 2f\n"

        /* stop condition again (in case of 32 not odd) */
        "mv a4, a1 \n"
        "srl a1, a1, 3 \n"
        "sll a1, a1, 3 \n"

        /* start loop */
        "1: \n"
        /*  load values */
        "   ld t1, 0(a0) \n"

        /*  add elements */
        /*  in_a[i] + in_b[i] */
        "   add t0, t1, t2 \n"
        /*  add carry */
        "   add t0, t0, a5 \n"
        /*  if res <  in_a[i] */
        "   sltu a5, t0, t1 \n"

        /*  store 32 bits result */
        "   sd t0, 0(a0) \n"

        /*  update pointer addr */
        "   addi a0, a0, 8 \n"

        /*  set t2 to zero */
        "   mv t2, zero \n"

        "   bltu a0, a1, 1b \n"

        /*  in case the last block was 64 bits return */
        "   beq a4, a1, 3f \n"

        "2: \n"
        /*  load values */
        "   lwu t1, 0(a0) \n"

        /*  add elements */
        /*  in_a[i] + in_b[i] */
        "   add t0, t1, t2 \n"
        /*  add carry */
        "   add t0, t0, a5 \n"
        /*  upper 32 bits of register t0 contains carry */
        "   srli a5, t0, 32 \n"

        /* store 32 bits result */
        "   sw t0, 0(a0) \n"

        /* return carry (a5) */
        "3: \n"
        "   mv a0, a5 \n"
        "   ret \n" ::
            :);
#else
#error Please reevalute this algorithm to check validity with this xlen
#endif

    /* just to clear warnings */
    return (0);
}

__attribute__((naked)) uint64_t soft_bignum_add(const uint64_t *const in_a,
                                                const uint64_t *const in_b,
                                                uint64_t *const out,
                                                size_t nb_32b_words)
{
    /* just to clear warnings */
    (void)in_a;
    (void)in_b;
    (void)out;
    (void)nb_32b_words;

    /**
     * just as a reminder:
     * in_a => a0 register
     * in_b => a1 register
     * out => a2 register
     * nb_32b_words => a3 register
     */

#if __riscv_xlen == 32
    __asm__ __volatile__(
        /* init carry to 0 */
        "mv a5, zero \n"

        /* check word_size is >0 and < 0x3FFFFFFF*/
        "li t1, 0x3FFFFFFF \n"
        "beqz a3, 2f\n"
        "bgtu a3, t1, 2f\n"

        /* stop condition */
        "slli a3, a3, 2 \n"
        "add a3, a0, a3 \n"

        /* start loop */
        "1: \n"
        /*  load values */
        "   lw t1, 0(a0) \n"
        "   lw t2, 0(a1) \n"

        /*  add elements */
        /*  in_a[i] + in_b[i] */
        "   add t0, t1, t2 \n"
        /*  add carry */
        "   add t0, t0, a5 \n"
        /*  if res <  in_a[i] */
        "   sltu a5, t0, t1 \n"

        /*  store 32 bits result */
        "   sw t0, 0(a2) \n"

        /*  update pointer addr */
        "   addi a0, a0, 4 \n"
        "   addi a1, a1, 4 \n"
        "   addi a2, a2, 4 \n"

        "   bltu a0, a3, 1b \n"

        /* return carry (a5) */
        "2: \n"
        "   mv a0, a5 \n"
        "   mv a1, zero \n"
        "   ret \n" ::
            :);
#elif __riscv_xlen == 64
    __asm__ __volatile__(
        /* init carry to 0 */
        "mv a5, zero \n"

        /* check word_size is >0 and < 0x3FFFFFFF*/
        "li t1, 0x3FFFFFFF \n"
        "beqz a3, 3f\n"
        "bgtu a3, t1, 3f\n"

        /* stop condition */
        "slli a3, a3, 2 \n"
        "add a3, a0, a3 \n"

        /* case there is only one 32bit word */
        "addi a4, a0, 4 \n"
        "beq a3, a4, 2f\n"

        /* stop condition again (in case of 32 not odd) */
        "mv a4, a3 \n"
        "srl a3, a3, 3 \n"
        "sll a3, a3, 3 \n"

        /* start loop */
        "1: \n"
        /*  load values */
        "   ld t1, 0(a0) \n"
        "   ld t2, 0(a1) \n"

        /*  add elements */
        /*  in_a[i] + in_b[i] */
        "   add t0, t1, t2 \n"
        /*  add carry */
        "   add t0, t0, a5 \n"
        /*  if res <  in_a[i] */
        "   sltu a5, t0, t1 \n"

        /*  store 32 bits result */
        "   sd t0, 0(a2) \n"

        /*  update pointer addr */
        "   addi a0, a0, 8 \n"
        "   addi a1, a1, 8 \n"
        "   addi a2, a2, 8 \n"

        "   bltu a0, a3, 1b \n"

        /*  in case the last block was 64 bits return */
        "   beq a4, a3, 3f \n"

        "2: \n"
        /*  load values */
        "   lwu t1, 0(a0) \n"
        "   lwu t2, 0(a1) \n"

        /*  add elements */
        /*  in_a[i] + in_b[i] */
        "   add t0, t1, t2 \n"
        /*  add carry */
        "   add t0, t0, a5 \n"
        /*  upper 32 bits of register t0 contains carry */
        "   srli a5, t0, 32 \n"

        /* store 32 bits result */
        "   sw t0, 0(a2) \n"

        /* return carry (a5) */
        "3: \n"
        "   mv a0, a5 \n"
        "   ret \n" ::
            :);
#else
#error Please reevalute this algorithm to check validity with this xlen
#endif

    /* just to clear warnings */
    return (0);
}

__attribute__((naked)) uint32_t soft_bignum_sub(const uint64_t *const in_a,
                                                const uint64_t *const in_b,
                                                uint64_t *const out,
                                                size_t nb_32b_words)
{
    /* just to clear warnings */
    (void)in_a;
    (void)in_b;
    (void)out;
    (void)nb_32b_words;

    /**
     * just as a reminder:
     * in_a => a0 register
     * in_b => a1 register
     * out => a2 register
     * nb_32b_words => a3 register
     */

#if __riscv_xlen == 32
    __asm__ __volatile__(
        /* init carry to 0 */
        "mv a5, zero \n"

        /* check word_size is >0 and < 0x3FFFFFFF*/
        "li t1, 0x3FFFFFFF \n"
        "beqz a3, 2f\n"
        "bgtu a3, t1, 2f\n"

        /* stop condition */
        "slli a3, a3, 2 \n"
        "add a3, a0, a3 \n"

        /* start loop */
        "1: \n"
        /*  load values */
        "   lw t1, 0(a0) \n"
        "   lw t2, 0(a1) \n"

        /*  sub elements */
        /*  add carry to t2*/
        "   sub a5, t1, a5 \n"
        "   sltu a4, t1, a5 \n"
        /*  in_a[i] - in_b[i] */
        "   sub t0, a5, t2 \n"
        /*  if res >  in_a[i] */
        "   sltu a5, a5, t0 \n"
        "   or a5, a5, a4 \n"

        /*  store 32 bits result */
        "   sw t0, 0(a2) \n"

        /*  update pointer addr */
        "   addi a0, a0, 4 \n"
        "   addi a1, a1, 4 \n"
        "   addi a2, a2, 4 \n"

        "   bltu a0, a3, 1b \n"

        /* return carry (a5) */
        "2: \n"
        "   mv a0, a5 \n"
        "   mv a1, zero \n"
        "   ret \n" ::
            :);
#elif __riscv_xlen == 64
    __asm__ __volatile__(
        /* init carry to 0 */
        "mv a5, zero \n"

        /* check word_size is >0 and < 0x3FFFFFFF*/
        "li t1, 0x3FFFFFFF \n"
        "beqz a3, 3f\n"
        "bgtu a3, t1, 3f\n"

        /* stop condition */
        "slli a3, a3, 2 \n"
        "add a3, a0, a3 \n"

        /* case there is only one 32bit word */
        "addi a4, a0, 4 \n"
        "beq a3, a4, 2f\n"

        /* stop condition again (in case of 32 not odd) */
        "mv a4, a3 \n"
        "srl a3, a3, 3 \n"
        "sll a3, a3, 3 \n"

        /* start loop */
        "1: \n"
        /*  load values */
        "   ld t1, 0(a0) \n"
        "   ld t2, 0(a1) \n"

        /*  sub elements */
        /*  sub carry */
        "   sub a5, t1, a5 \n"
        /*  if res >  in_a[i] */
        "   sltu a6, t1, a5 \n"
        /*  in_a[i] + in_b[i] */
        "   sub t0, a5, t2 \n"
        /*  if res >  in_a[i] */
        "   sltu a5, a5, t0 \n"
        "   or a5, a5, a6 \n"

        /*  store 32 bits result */
        "   sd t0, 0(a2) \n"

        /*  update pointer addr */
        "   addi a0, a0, 8 \n"
        "   addi a1, a1, 8 \n"
        "   addi a2, a2, 8 \n"

        "   bltu a0, a3, 1b \n"

        /*  in case the last block was 64 bits return */
        "   beq a4, a3, 3f \n"

        "2: \n"
        /*  load values */
        "   lwu t1, 0(a0) \n"
        "   lwu t2, 0(a1) \n"

        /*  sub elements */
        /*  sub carry */
        "   sub a5, t1, a5 \n"
        /*  if res >  in_a[i] */
        "   sltu a6, t1, a5 \n"
        /*  in_a[i] + in_b[i] */
        "   sub t0, a5, t2 \n"
        /*  if res >  in_a[i] */
        "   sltu a5, a5, t0 \n"
        "   or a5, a5, a6 \n"

        /* store 32 bits result */
        "   sw t0, 0(a2) \n"

        /* return carry (a5) */
        "3: \n"
        "   mv a0, a5 \n"
        "   ret \n" ::
            :);
#else
#error Please reevalute this algorithm to check validity with this xlen
#endif

    /* just to clear warnings */
    return (0);
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
