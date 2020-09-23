/**
 * @file test_soft_bignumbers_runner.c
 * @brief test runner for test_soft_bignumbers.c
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP_RUNNER(soft_bignumbers)
{
    /* addition */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_size_1_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_size_2_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_size_5_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_summ_all_FF);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_carry_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_carry_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_in_a_is_output);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_in_b_is_output);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_add_100_bytes);

    /* substraction */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_1_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_2_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_5_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_size_5_with_carry_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_in_a_is_output);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_sub_in_b_is_output);

    /* increment by one */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_inc_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_inc_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_inc_size_1_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_inc_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_inc_size_2_with_carry);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_inc_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_inc_size_5_with_carry);

    /* test compare */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_a_equals_b);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_a_greater_than_b_lsb);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_a_greater_than_b_msb);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_a_lower_than_b_lsb);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_a_lower_than_b_msb);

    /* multiplication */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mult_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mult_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mult_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mult_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mult_size_5_zero);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mult_size_5_identity);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mult_size_12);

    /* Right shift */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_7);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_5_shift_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_5_shift_159);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_5_shift_160);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_5_shift_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_5_in_NULL);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_5_out_NULL);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_rightshift_size_7_shift_59);

    /* Left Shift */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_7);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5_shift_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5_shift_159);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5_shift_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5_shift_160);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5_in_NULL);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5_out_NULL);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_7_shift_59);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_leftshift_size_5_shift_39);

    /* test on msb set in word */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_msb_set_in_word_32b_word);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_msb_set_in_word_64b_word_last_bit_set);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_msb_set_in_word_64b_word_first_bit_set);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_msb_set_in_word_32b_word_none_set);

    /* check bignumber null */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_is_null_size_6_lsb_set);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_is_null_size_6_msb_set);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_is_null_size_5_msb_set);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_is_null_size_6_null);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_is_null_size_5_null);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_is_null_array_nullptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_is_null_size_0);

    /* Get MSB set in bignumber */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_get_msb_set_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_get_msb_set_nullptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_get_msb_set_size_5_expect_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_get_msb_set_size_5_expect_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_get_msb_set_size_5_expect_159);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_get_msb_set_size_5_124);

    /* set one bit in a big integer */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_set_bit_null_ptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_set_bit_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_set_bit_size_5_set_first);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_set_bit_size_5_set_last);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_set_bit_size_5_set_out_of_range);

    /* Compare with different length */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_len_diff_a_equals_b);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_compare_len_diff_a_greater_than_b_lsb);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_compare_len_diff_a_greater_than_b_msb);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_compare_len_diff_a_lower_than_b_lsb);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_compare_len_diff_a_lower_than_b_msb);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_compare_len_diff_a_equals_b_len_a_greater);
    RUN_TEST_CASE(
        soft_bignumbers,
        soft_bignum_compare_len_diff_a_greater_than_b_lsb_len_a_greater);
    RUN_TEST_CASE(
        soft_bignumbers,
        soft_bignum_compare_len_diff_a_lower_than_b_lsb_len_a_greater);
    RUN_TEST_CASE(soft_bignumbers,
                  soft_bignum_compare_len_diff_a_equals_b_len_b_greater);
    RUN_TEST_CASE(
        soft_bignumbers,
        soft_bignum_compare_len_diff_a_greater_than_b_lsb_len_a_greater);
    RUN_TEST_CASE(
        soft_bignumbers,
        soft_bignum_compare_len_diff_a_lower_than_b_lsb_len_a_greater);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_len_diff_len_a_greater);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_compare_len_diff_len_b_greater);

    /* div */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_div_by_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_div_dividend_null_ptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_div_divisor_null_ptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_div_dividend_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_div_divisor_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_div_dividend_lt_divisor);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_div_dividend_gt_divisor);

    /* Modulus computation */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_modulus_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_input_null_ptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_modulus_null_ptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_input_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_modulus_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_input_lt_modulus);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_input_gt_modulus);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_input_gt_modulus_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_size_12);

    /* Modular addition */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_1_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_2_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_add_size_5_2);

    /* Negate */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_negate_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_negate_nullptr);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_negate_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_negate_size_1_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_negate_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_negate_size_5_2);

    /* Modular subtraction */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_1_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_2_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_2_3);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_sub_size_5_2);

    /* Negate mod */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_neg_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_neg_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_neg_size_1_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_neg_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_neg_size_2_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_neg_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_neg_size_5_2);

    /* Modular multiplication */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_1_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_2_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_5_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_mult_size_12);

    /* Modular multiplicative inverse */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_1_not_inversible);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_1_err_parity);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_1_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_2_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_5_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_inv_size_5_not_inversible);

    /* square */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_square_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_square_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_square_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_square_size_5);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_square_size_5_zero);

    /* Mod square */
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_square_size_0);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_square_size_1);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_square_size_1_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_square_size_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_square_size_2_2);
    RUN_TEST_CASE(soft_bignumbers, soft_bignum_mod_square_size_5);
}
