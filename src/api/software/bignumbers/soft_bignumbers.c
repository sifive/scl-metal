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

        /* case there is only one 32bit word */
        "addi a4, a0, 4 \n"
        "beq a1, a4, 2f\n"

        /* stop condition again (in case of 32 not odd) */
        "mv a4, a1 \n"
        "srl a1, a1, 3 \n"
        "sll a1, a1, 3 \n"

        /* init t2 */
        "li t2, 1 \n"

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

#if 0

void soft_bignum_mult(const uint64_t *const in_a, const uint64_t *const in_b,
                      uint64_t *const out, const uint64_t *const modulus,
                      size_t nb_32b_words)
{
    size_t i, j;
    uint32_t carry, yi;
    uint64_t uv;

    scl_bignum_memset(w, 0, 2 * word_size);
    // 1.
    for (i = 0; i < word_size; i++)
    {
        // 2.1,2.2
        yi = y[i];
        for (carry = 0, j = 0; j < word_size; j++)
        {
            uv = (uint64_t)yi * (uint64_t)x[j];
            if ((w[i + j] = w[i + j] + carry) < carry)
                carry = 1;
            else
                carry = 0;
            if ((w[i + j] += (uv & SCL_WORD_MAX_VALUE)) <
                (uv & SCL_WORD_MAX_VALUE))
                carry++;
            carry += (uv >> SCL_WORD_BITS);
        }
        w[i + word_size] += carry;
    }
}

void scl_bignum_mult_hoac(uint32_t *w, uint32_t *x, uint32_t *y, int word_size)
{
    int i, j;
    uint32_t carry, yi;
    uint64_t uv;
    scl_bignum_memset(w, 0, 2 * word_size);
    // 1.
    for (i = 0; i < word_size; i++)
    {
        // 2.1,2.2
        yi = y[i];
        for (carry = 0, j = 0; j < word_size; j++)
        {
            uv = (uint64_t)yi * (uint64_t)x[j];
            if ((w[i + j] = w[i + j] + carry) < carry)
                carry = 1;
            else
                carry = 0;
            if ((w[i + j] += (uv & SCL_WORD_MAX_VALUE)) <
                (uv & SCL_WORD_MAX_VALUE))
                carry++;
            carry += (uv >> SCL_WORD_BITS);
        }
        w[i + word_size] += carry;
    }
}

#endif
/*************************************************/
/*              Progress Line                    */
/*************************************************/
#if 0


//(uint32_t) big numbers format
// natural-coding lsW is in [0]

ith bit extraction
CRYPTO_FUNCTION int32_t scl_word_bit(uint32_t *x, int i)
{
    if (x[i / SCL_WORD_BITS] &
        ((uint32_t)1 << ((uint32_t)(i % SCL_WORD_BITS)))) {
        return (1);
    } else {
        return (0);
    }
}

void scl_bignum_truncate(uint32_t *x, int bit_size, int word_size)
{
    int i, word_index, bit_index;
    int shift;
    // if the truncation request is useless
    if (word_size * 32 < bit_size)
        return;
    // compute the last full word position
    word_index = (bit_size / (sizeof(uint32_t) * SCL_BYTE_BITS));
    // compute how many bits in the last incomplete word
    bit_index = bit_size % (sizeof(uint32_t) * SCL_BYTE_BITS);
    // if no incomplete word (should be the most frequent case)
    if (0 == bit_index) {
        i = word_index;
    } else {
        // cleaning the extra bits,by left shift then right shift
        shift = sizeof(uint32_t) * SCL_BYTE_BITS - bit_index;
        x[word_index] = (x[word_index] << shift) >> shift;
        i = word_index + 1;
    }
    // cleaning remaining words
    for (; i < word_size; i++) {
        x[i] = 0;
    }
}

// looking for the first non null word
int scl_bignum_words_in_number(uint32_t *n, int word_size)
{
    int i;
    for (i = word_size - 1; i >= 0; i--) {
        if (n[i]) {
            break;
        }
    }
    return (i + 1);
}

void scl_bignum_set_one_word(uint32_t *array, uint32_t the_word, int word_size)
{
    int i;
    array[0] = the_word;
    for (i = 1; i < word_size; i++) {
        array[i] = 0;
    }
}


// compare a and b, a with a declared larger size than b
METAL_OPTIMIZE_CODE int scl_bignum_memcmp_sizes(uint32_t *a, int a_size,
                                                uint32_t *b, int b_size)
{
    if (scl_bignum_words_in_number(a, a_size) > b_size) {
        return (1);
    }
    return (scl_bignum_memcmp(a, b, b_size));
}

METAL_OPTIMIZE_CODE void scl_bignum_set_zero(uint32_t *array, int word_size)
{
    scl_bignum_memset(array, 0, word_size);
}

METAL_OPTIMIZE_CODE int scl_bignum_bits_in_word(uint32_t a)
{
    int i;
    for (i = 0; i < SCL_WORD_BITS; i++, a >>= 1) {
        if (!a) {
            break;
        }
    }
    return (i);
}

METAL_OPTIMIZE_CODE int scl_bignum_secure_memcmp(uint32_t *a, uint32_t *b,
                                                 int word_size)
{
    int i;
    int ret = 0;
    for (i = 0; i < word_size; i++) {
        ret += a[i] > b[i];
        ret -= a[i] < b[i];
    }
    return (ret);
}

int scl_bignum_lt_zero(uint32_t *a, int word_size)
{
    if (a[word_size - 1] == SCL_WORD_MAX_VALUE) {
        return (SCL_TRUE);
    } else {
        return (SCL_FALSE);
    }
}

// return SCL_OK when a is zero, SCL_ERROR when a is different from zero
METAL_OPTIMIZE_CODE int scl_bignum_cmp_with_zero(uint32_t *a, int word_size)
{
    int i;
    for (i = 0; i < word_size; i++) {
        if (a[i]) {
            return (SCL_ERROR);
        }
    }
    return (SCL_OK);
}

// constant-time comparison with zero, same result than above
int scl_bignum_secure_cmp_with_zero(uint32_t *a, int word_size)
{
    int i;
    int ret = 0;
    for (i = 0; i < word_size; i++) {
        ret |= (a[i] != 0);
    }
    ret = (!ret) ? SCL_OK : SCL_ERROR;
    return (ret);
}

// using a double word should use the computation and using the union eases the
// data recovery
void scl_bignum_mult_one_word(uint32_t *r, uint32_t x, uint32_t y)
{
    union two_words_in_a_double_word {
        uint64_t dw;
        uint32_t w[2];
    } n;
    n.dw = (uint64_t)x * (uint64_t)y;
    r[0] = n.w[0];
    r[1] = n.w[1];
}

// using a double word should use the computation
void scl_bignum_div_one_word(uint32_t *w, uint32_t x[2], uint32_t y)
{
    uint64_t n;
    n = (((uint64_t)x[1]) << SCL_WORD_BITS) ^ ((uint64_t)x[0]);
    *w = (uint32_t)(n / y);
}


METAL_OPTIMIZE_CODE uint32_t scl_bignum_double_hoac(uint32_t *w, uint32_t *x,
                                                    int size)
{
    uint64_t wi;
    uint32_t carry;
    int i;
    for (carry = 0, i = 0; i < size; i++) {
        wi = 2 * (uint64_t)x[i] + (uint64_t)carry;
        carry = wi >> SCL_WORD_BITS;
        w[i] = wi; // which is the lW
    }
    return (carry);
}

METAL_OPTIMIZE_CODE uint32_t scl_bignum_double_hoac_8(uint32_t *w, uint32_t *x)
{
    uint64_t wi;
    uint32_t carry;
    wi = 2 * (uint64_t)x[0];
    carry = wi >> SCL_WORD_BITS;
    w[0] = wi;
    wi = 2 * (uint64_t)x[1] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[1] = wi;
    wi = 2 * (uint64_t)x[2] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[2] = wi;
    wi = 2 * (uint64_t)x[3] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[3] = wi;
    wi = 2 * (uint64_t)x[4] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[4] = wi;
    wi = 2 * (uint64_t)x[5] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[5] = wi;
    wi = 2 * (uint64_t)x[6] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[6] = wi;
    wi = 2 * (uint64_t)x[7] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[7] = wi;
    return (carry);
}

METAL_OPTIMIZE_CODE uint32_t scl_bignum_double_hoac_12(uint32_t *w, uint32_t *x)
{
    uint64_t wi;
    uint32_t carry;
    wi = 2 * (uint64_t)x[0];
    carry = wi >> SCL_WORD_BITS;
    w[0] = wi;
    wi = 2 * (uint64_t)x[1] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[1] = wi;
    wi = 2 * (uint64_t)x[2] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[2] = wi;
    wi = 2 * (uint64_t)x[3] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[3] = wi;
    wi = 2 * (uint64_t)x[4] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[4] = wi;
    wi = 2 * (uint64_t)x[5] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[5] = wi;
    wi = 2 * (uint64_t)x[6] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[6] = wi;
    wi = 2 * (uint64_t)x[7] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[7] = wi;
    wi = 2 * (uint64_t)x[8] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[8] = wi;
    wi = 2 * (uint64_t)x[9] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[9] = wi;
    wi = 2 * (uint64_t)x[10] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[10] = wi;
    wi = 2 * (uint64_t)x[11] + (uint64_t)carry;
    carry = wi >> SCL_WORD_BITS;
    w[11] = wi;
    return (carry);
}

METAL_OPTIMIZE_CODE uint32_t scl_bignum_double(uint32_t *w, uint32_t *x,
                                               int size)
{
    switch (size) {
    case SCL_SECP256R1_WORDSIZE:
        return (scl_bignum_double_hoac_8(w, x));
        break;
    case SCL_SECP384R1_WORDSIZE:
        return (scl_bignum_double_hoac_12(w, x));
        break;
    default:
        return (scl_bignum_double_hoac(w, x, size));
        break;
    }
}

// w=x+1
uint32_t scl_bignum_inc(uint32_t *w, uint32_t *x, int word_size)
{
    uint32_t *one, ret;
    if (SCL_OK != scl_stack_alloc(&one, word_size))
        return (SCL_STACK_ERROR);
    scl_bignum_set_one_word(one, 1, word_size);
    ret = scl_bignum_add(w, x, one, word_size);
    if (scl_stack_free(&one) != SCL_OK)
        return (SCL_STACK_ERROR);
    return (ret);
}

// Reverse Product Scanning Multiplication
METAL_OPTIMIZE_CODE void scl_bignum_mult_rps(uint32_t *r, uint32_t *a,
                                             uint32_t *b, int s)
{
    int i, j, k;
    uint64_t carry;
    uint64_t z, t;

    z = (uint64_t)a[0] * (uint64_t)b[0];
    r[0] = z & SCL_WORD_MAX_VALUE;
    z >>= SCL_WORD_BITS;
    carry = 0;
    // 3.
    for (i = 1; i <= s - 1; i++) {
        // 4.
        // 5.
        for (k = i, j = 0; j <= i; j++, k--) {
            // 6.
            // 7.
            t = (uint64_t)a[j] * (uint64_t)b[k];
            z += t;
            carry += (z < t);
        }
        // 9.
        r[i] = z;
        z >>= SCL_WORD_BITS;
        z ^= carry << SCL_WORD_BITS;
        carry = 0;
    }
    // 11.
    for (i = s; i <= 2 * s - 3; i++) {
        // 12.
        // 13.
        for (k = s - 1, j = i - (s - 1); j <= s - 1; j++, k--) {
            // 14.
            // 15.
            t = (uint64_t)a[j] * (uint64_t)b[k];
            z += t;
            carry += (z < t);
        }
        // 17.
        r[i] = z;
        z >>= SCL_WORD_BITS;
        z ^= carry << SCL_WORD_BITS;
        carry = 0;
    }
    // 19.
    z += (uint64_t)a[s - 1] * (uint64_t)b[s - 1];
    // 20.
    r[2 * s - 2] = z;
    r[2 * s - 1] = z >> SCL_WORD_BITS;
}

// HoAC 14.12
void scl_bignum_mult_hoac(uint32_t *w, uint32_t *x, uint32_t *y, int word_size)
{
    int i, j;
    uint32_t carry, yi;
    uint64_t uv;
    scl_bignum_memset(w, 0, 2 * word_size);
    // 1.
    for (i = 0; i < word_size; i++) {
        // 2.1,2.2
        yi = y[i];
        for (carry = 0, j = 0; j < word_size; j++) {
            uv = (uint64_t)yi * (uint64_t)x[j];
            if ((w[i + j] = w[i + j] + carry) < carry)
                carry = 1;
            else
                carry = 0;
            if ((w[i + j] += (uv & SCL_WORD_MAX_VALUE)) <
                (uv & SCL_WORD_MAX_VALUE))
                carry++;
            carry += (uv >> SCL_WORD_BITS);
        }
        w[i + word_size] += carry;
    }
}

// HoAC 14.12
METAL_OPTIMIZE_CODE void scl_bignum_mult_hoac2(uint32_t *w, uint32_t *x,
                                               uint32_t *y, int word_size)
{
    int i, j;
    uint64_t uv;
    uint32_t carry, u, v, wi, yi;
    scl_bignum_memset(w, 0, 2 * word_size);
    // 1.
    for (i = 0; i < word_size; i++) {
        // 2.1,2.2
        // storing in temp var helps
        yi = y[i];
        for (carry = 0, j = 0; j < word_size; j++) {
            // storing in temp var helps
            wi = w[i + j];
            carry = ((wi += carry) < carry);
            uv = (uint64_t)yi * (uint64_t)x[j];
            u = uv;
            v = uv >> SCL_WORD_BITS;
            carry += ((wi += u) < u) + v;
            w[i + j] = wi;
        }
        w[i + word_size] += carry;
    }
}

// faster than above on e31 but only when isolated
// not faster than above on e31 if combined with other routines (mod, add, sq)
// e.g. for ecdsa: is it because of cache behavior ?
METAL_OPTIMIZE_CODE void scl_bignum_mult_hoac2_8(uint32_t *w, uint32_t *x,
                                                 uint32_t *y)
{
    int i, j;
    uint64_t uv;
    uint32_t carry, u, v, yi, wi;
    scl_bignum_memset(w, 0, 2 * SCL_SECP256R1_WORDSIZE);
    // 1.
    for (i = 0; i < SCL_SECP256R1_WORDSIZE; i++) {
        // 2.1,2.2
        yi = y[i];
        carry = 0;
        j = 0;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 1;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 2;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 3;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 4;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 5;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 6;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 7;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;

        w[i + 8] += carry;
    }
}

METAL_OPTIMIZE_CODE void scl_bignum_mult_hoac2_12(uint32_t *w, uint32_t *x,
                                                  uint32_t *y)
{
    int i, j;
    uint64_t uv;
    uint32_t carry, u, v, yi, wi;
    scl_bignum_memset(w, 0, 2 * SCL_SECP384R1_WORDSIZE);
    // 1.
    for (i = 0; i < SCL_SECP384R1_WORDSIZE; i++) {
        // 2.1,2.2
        yi = y[i];
        carry = 0;
        j = 0;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 1;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 2;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 3;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 4;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 5;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 6;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 7;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;

        j = 8;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 9;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 10;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;
        j = 11;
        wi = w[i + j];
        uv = ((uint64_t)yi * (uint64_t)x[j]);
        u = uv;
        v = uv >> SCL_WORD_BITS;
        carry = ((wi += carry) < carry);
        carry += ((wi += u) < u) + v;
        w[i + j] = wi;

        w[i + 12] += carry;
    }
}

METAL_OPTIMIZE_CODE void scl_bignum_mult(uint32_t *w, uint32_t *x, uint32_t *y,
                                         int word_size)
{
    //#if !defined(rv32imac)
    switch (word_size) {
    case SCL_SECP256R1_WORDSIZE:
        return (scl_bignum_mult_hoac2_8(w, x, y));
        break;
    case SCL_SECP384R1_WORDSIZE:
        return (scl_bignum_mult_hoac2_12(w, x, y));
        break;
    default:
        return (scl_bignum_mult_hoac2(w, x, y, word_size));
        break;
    }
}

// HoAC 14.16
METAL_OPTIMIZE_CODE void scl_bignum_square_hoac(uint32_t *w, uint32_t *x,
                                                int word_size)
{
    int i, j;
    uint64_t uv, tmp, u, xi;
    uint32_t carry;
    scl_bignum_memset(w, 0, 2 * word_size);
    // 1.
    for (i = 0; i < word_size; i++) {
        // 2.1
        xi = x[i];
        uv = xi * xi + (uint64_t)w[i + i];
        w[i + i] = uv;
        u = uv >> SCL_WORD_BITS;
        // 2.2
        for (j = i + 1; j < word_size; j++) {
            uv = xi * (uint64_t)x[j];
            tmp = (uint64_t)w[i + j] + u;
            carry = tmp < u;           // 1 if overflow
            carry += (tmp += uv) < uv; //+1 if overflow
            carry += (tmp += uv) < uv; //+1 if overflow
            w[i + j] = tmp;
            u = ((uint64_t)carry << SCL_WORD_BITS) +
                (tmp >> SCL_WORD_BITS); // carry is on double word
        }
        // extra carry management
        j = word_size;
        while (u > 0) {
            tmp = (uint64_t)w[i + j] + u;
            w[i + j] = tmp;
            u = tmp >> SCL_WORD_BITS;
            j++;
        }
    }
}

METAL_OPTIMIZE_CODE void scl_bignum_square(uint32_t *w, uint32_t *x,
                                           int word_size)
{
#if !defined(rv32imac)
    scl_bignum_square_hoac(w, x, word_size);
#else
    scl_bignum_mult(w, x, x, word_size);
#endif
}

uint32_t scl_bignum_sub_and_mult_one_word(uint32_t *a, uint32_t *b, uint32_t c,
                                          uint32_t *d, int word_size)
{
    uint32_t borrow, atmp, t[2], val;
    int i;
    if (0 == c)
        return (0);
    for (borrow = 0, i = 0; i < word_size; i++) {
        scl_bignum_mult_one_word(t, c, d[i]);
        atmp = b[i] - borrow;
        val = SCL_WORD_MAX_VALUE - borrow;
        if (atmp > val)
            borrow = 1;
        else
            borrow = 0;
        atmp -= t[0];
        val = SCL_WORD_MAX_VALUE - t[0];
        if (atmp > val)
            borrow++;
        borrow += t[1];
        a[i] = atmp;
    }
    return (borrow);
}

METAL_OPTIMIZE_CODE uint32_t scl_bignum_leftshift(uint32_t *a, uint32_t *b,
                                                  int shift, int word_size)
{
    uint32_t bi, borrow;
    int revshift, wnb, bnb;
    int i;
    wnb = shift / SCL_WORD_BITS;
    bnb = shift & (SCL_WORD_BITS - 1);
    if (0 == bnb)
        revshift = 0;
    else
        revshift = SCL_WORD_BITS - bnb;
    scl_bignum_memset(a, 0, wnb);
    for (borrow = 0, i = 0; i < word_size; i++) {
        bi = b[i];
        a[i + wnb] = (borrow | (bi << bnb));
        borrow = bnb ? (bi >> revshift) : 0;
    }
    return (borrow);
}

METAL_OPTIMIZE_CODE uint32_t scl_bignum_rightshift(uint32_t *a, uint32_t *b,
                                                   int shift, int word_size)
{
    uint32_t bi, carry;
    int revshift, wnb, bnb;
    int i;
    bnb = shift & (SCL_WORD_BITS - 1);
    wnb = shift / SCL_WORD_BITS;
    if (0 == bnb)
        revshift = 0;
    else
        revshift = SCL_WORD_BITS - bnb;
    carry = 0;
    for (i = word_size - 1 - wnb; i >= 0; i--) {
        bi = b[i + wnb];
        a[i] = (carry | (bi >> bnb));
        carry = bnb ? (bi << revshift) : 0;
    }
    return (carry);
}

METAL_OPTIMIZE_CODE int scl_bignum_div(uint32_t *remainder, uint32_t *quotient,
                                       uint32_t *a, int a_word_size,
                                       uint32_t *b, int b_word_size)
{
    uint32_t atmp, *ctmp, *dtmp, t;
    int i;
    uint32_t *work;
    uint32_t b_real_word_size, shift;
    b_real_word_size = scl_bignum_words_in_number(b, b_word_size);
    if (0 == b_real_word_size)
        return (SCL_OK);
    if (SCL_OK != scl_stack_alloc(&work, a_word_size + b_word_size + 2))
        return (SCL_STACK_OVERFLOW);
    ctmp = work;
    dtmp = ctmp + a_word_size + 1;
    shift = SCL_WORD_BITS - scl_bignum_bits_in_word(b[b_real_word_size - 1]);
    scl_bignum_memset(ctmp, 0, b_real_word_size);
    ctmp[a_word_size] = scl_bignum_leftshift(ctmp, a, shift, a_word_size);
    scl_bignum_leftshift(dtmp, b, shift, b_real_word_size);
    t = dtmp[b_real_word_size - 1];
    for (i = a_word_size - b_real_word_size; i >= 0; i--) {
        if (SCL_WORD_MAX_VALUE == t)
            atmp = ctmp[i + b_real_word_size];
        else
            scl_bignum_div_one_word(&atmp, &ctmp[i + b_real_word_size - 1],
                                    t + 1);
        ctmp[i + b_real_word_size] -= scl_bignum_sub_and_mult_one_word(
            &ctmp[i], &ctmp[i], atmp, dtmp, b_real_word_size);
        while (ctmp[i + b_real_word_size] ||
               (scl_bignum_memcmp(&ctmp[i], dtmp, b_real_word_size) >= 0)) {
            atmp++;
            ctmp[i + b_real_word_size] -=
                scl_bignum_sub(&ctmp[i], &ctmp[i], dtmp, b_real_word_size);
        }
        if (NULL != quotient)
            quotient[i] = atmp;
    }
    if (NULL != remainder)
        scl_bignum_rightshift(remainder, ctmp, shift, b_real_word_size);
    if (scl_stack_free(&work) != SCL_OK)
        return (SCL_STACK_ERROR);
    return (SCL_OK);
}

// r=a mod modulus
METAL_OPTIMIZE_CODE int scl_bignum_mod(uint32_t *rmd, uint32_t *a,
                                       int a_word_size, uint32_t *modulus,
                                       int word_size)
{
    return (scl_bignum_div(rmd, NULL, a, a_word_size, modulus, word_size));
}

int scl_bignum_modmult(uint32_t *r, uint32_t *a, uint32_t *b, uint32_t *modulus,
                       int word_size)
{
    int ret;
    uint32_t *mult;
    if (SCL_OK != scl_stack_alloc(&mult, word_size * 2))
        return (SCL_STACK_OVERFLOW);
    scl_bignum_mult(mult, a, b, word_size);
    ret = scl_bignum_mod(r, mult, 2 * word_size, modulus, word_size);
    if (scl_stack_free(&mult) != SCL_OK)
        return (SCL_STACK_ERROR);
    if (SCL_OK != ret)
        return (ret);
    return (SCL_OK);
}

int scl_bignum_modsquare(uint32_t *r, uint32_t *a, uint32_t *modulus,
                         int word_size)
{
    int resu;
    uint32_t *mult;
    if (SCL_OK != scl_stack_alloc(&mult, word_size * 2))
        return (SCL_STACK_OVERFLOW);
    scl_bignum_square(mult, a, word_size);
    resu = scl_bignum_mod(r, mult, 2 * word_size, modulus, word_size);
    if (scl_stack_free(&mult) != SCL_OK)
        return (SCL_STACK_ERROR);
    if (SCL_OK != resu)
        return (resu);
    return (SCL_OK);
}

int scl_bignum_modadd(uint32_t *r, uint32_t *a, uint32_t *b, uint32_t *modulus,
                      int word_size)
{
    int resu;
    uint32_t *add;
    if (SCL_OK != scl_stack_alloc(&add, word_size + 1))
        return (SCL_STACK_OVERFLOW);
    add[word_size] = scl_bignum_add(add, a, b, word_size);
    resu = scl_bignum_mod(r, add, word_size + 1, modulus, word_size);
    if (scl_stack_free(&add) != SCL_OK)
        return (SCL_STACK_ERROR);
    if (SCL_OK != resu)
        return (resu);
    return (SCL_OK);
}

// NIST FIPS 186-4
// not working yet
int scl_bignum_modinv_fips(uint32_t *zinv, uint32_t *z, uint32_t *a,
                           int word_size)
{
    int ret;
    uint32_t *i, *j, *y2, *y1, *work, *quotient, *remainder, *tmp, *one, *y;
    ret = SCL_OK;
    if (NULL == a || NULL == z)
        return (SCL_INVALID_INPUT);
    if (NULL == zinv)
        return (SCL_INVALID_OUTPUT);
    // 1.
    if (scl_bignum_memcmp(z, a, word_size) >= 0)
        return (SCL_INVALID_INPUT);
    if (scl_stack_alloc(&work, word_size * 9) != SCL_OK)
        return (SCL_STACK_OVERFLOW);
    i = work;
    j = i + word_size;
    y1 = j + word_size;
    y2 = y1 + word_size;
    quotient = y2 + word_size;
    remainder = quotient + word_size;
    tmp = remainder + word_size;
    one = tmp + word_size;
    y = one + word_size;
    // 2.
    scl_bignum_memcpy(i, a, word_size);
    scl_bignum_memcpy(j, z, word_size);
    scl_bignum_memset(y2, 0, word_size);
    scl_bignum_set_one_word(y1, 1, word_size);
    scl_bignum_set_one_word(one, 1, word_size);
    // 3. quotient and remainder computation
    while (SCL_ERROR == scl_bignum_cmp_with_zero(j, word_size)) {
        // 3.4.
        scl_bignum_div(remainder, quotient, i, word_size, j, word_size);
        // 5 y=y2-(y1*quotient)
        // tmp=y1*quotient
        scl_bignum_mult(tmp, y1, quotient, word_size);
        // y=y2-tmp
        scl_bignum_sub(y, y2, tmp, word_size);
        // 6. i=j, j=remainder, y2=y1, y1=y
        scl_bignum_memcpy(i, j, word_size);
        scl_bignum_memcpy(j, remainder, word_size);
        scl_bignum_memcpy(y2, y1, word_size);
        scl_bignum_memcpy(y1, y, word_size);
    }
    // 8.if(i!=1) return ERROR
    if (scl_bignum_memcmp(i, one, word_size) != 0)
        ret = SCL_ERROR;
    else
        // 9. return y2 mod a
        scl_bignum_mod(zinv, y2, word_size, a, word_size);
    if (scl_stack_free(&work) != SCL_OK)
        return (SCL_STACK_ERROR);
    return (ret);
}

/*
METAL_OPTIMIZE_CODE int scl_bignum_modinv_fermat(uint32_t *x,uint32_t
*a,uint32_t *b,int word_size)
{
  //compute a⁽b-2⁾ mod b
  }*/

// HoAC,algo 14.61
METAL_OPTIMIZE_CODE int scl_bignum_modinv(uint32_t *x, uint32_t *a, uint32_t *b,
                                          int word_size)
{
    uint32_t *work, *u, *v, *aext, *xext;
    if (scl_stack_alloc(&work, word_size * 3 + 2) != SCL_OK)
        return (SCL_STACK_OVERFLOW);
    // we want to save an array, so we use x for u
    // u is not used at the end
    // u=work;
    // v=u+word_size;
    u = x;
    v = work;
    aext = v + word_size;
    xext = aext + word_size + 1;

    scl_bignum_memcpy(u, a, word_size);
    scl_bignum_memcpy(v, b, word_size);
    scl_bignum_set_one_word(aext, 1, word_size);
    scl_bignum_memset(xext, 0, word_size);
    while (SCL_ERROR == scl_bignum_cmp_with_zero(u, word_size)) {
        while (0 == (u[0] & 1)) {
            scl_bignum_rightshift(u, u, 1, word_size);
            if (0 == (aext[0] & 1)) {
                scl_bignum_rightshift(aext, aext, 1, word_size);
            } else {
                aext[word_size] = scl_bignum_add(aext, aext, b, word_size);
                scl_bignum_rightshift(aext, aext, 1, word_size + 1);
            }
        }
        while (0 == (v[0] & 1)) {
            scl_bignum_rightshift(v, v, 1, word_size);
            if (0 == (xext[0] & 1)) {
                scl_bignum_rightshift(xext, xext, 1, word_size);
            } else {
                xext[word_size] = scl_bignum_add(xext, xext, b, word_size);
                scl_bignum_rightshift(xext, xext, 1, word_size + 1);
            }
        }
        if (scl_bignum_memcmp(u, v, word_size) >= 0) {
            scl_bignum_sub(u, u, v, word_size);
            if (scl_bignum_memcmp(aext, xext, word_size) < 0) {
                scl_bignum_add(aext, aext, b, word_size);
            }
            scl_bignum_sub(aext, aext, xext, word_size);
        } else {
            scl_bignum_sub(v, v, u, word_size);
            if (scl_bignum_memcmp(xext, aext, word_size) < 0) {
                scl_bignum_add(xext, xext, b, word_size);
            }
            scl_bignum_sub(xext, xext, aext, word_size);
        }
    }
    scl_bignum_memcpy(x, xext, word_size);
    if (scl_stack_free(&work) != SCL_OK)
        return (SCL_STACK_ERROR);
    return (SCL_OK);
}

#endif
/*****************************************************/
/*              end Progress Line                    */
/*****************************************************/
