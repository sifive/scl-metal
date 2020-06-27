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
#include <scl/scl_retdefs.h>

#include <api/software/bignumbers/soft_bignumbers.h>

// extern uint32_t zero[SCL_SECP521R1_WORDSIZE];

void soft_bignum_zeroise(uint64_t *const array, size_t nb_64b_words)
{
    size_t i;
    for (i = 0; i < nb_64b_words; i++)
    {
        array[i] = 0;
    }
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

// w = in_a - in_b, in_a > in_b
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
