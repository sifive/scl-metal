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
 * @file utils.h
 * @brief Low level API common utilitarian functions
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef SCL_BACKEND_UTILS_H
#define SCL_BACKEND_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <crypto_cfg.h>

/**
 * @addtogroup COMMON
 * @addtogroup UTILS
 * @ingroup COMMON
 *  @{
 */

/**
 * @brief copy 8 bits array into unsigned 32 bits array (big endian)
 *
 * @param[out] dest         destination buffer (uint32_t)
 * @param[in] src           source buffer (uint8_t)
 * @param[in] len           length to copy in byte
 * @return SCL_OK           In case of success
 * @return SCL_ERROR        In case of failure
 * @warning lenght to copy shall be a multiple of 4 bytes
 */
CRYPTO_FUNCTION int32_t copy_u8_2_u32_be(uint32_t *const dest,
                                         const uint8_t *const src, size_t len);

/**
 * @brief copy 8 bits array into unsigned 64 bits array (big endian)
 *
 * @param[out] dest         destination buffer (uint32_t)
 * @param[in] src           source buffer (uint8_t)
 * @param[in] len           length to copy in byte
 * @return SCL_OK           In case of success
 * @return SCL_ERROR        In case of failure
 * @warning lenght to copy shall be a multiple of 8 bytes
 */
CRYPTO_FUNCTION int32_t copy_u8_2_u64_be(uint64_t *const dest,
                                         const uint8_t *const src, size_t len);

/**
 * @brief copy 8 bits array into unsigned 64 bits array (big endian)
 *
 * @param[out] dest         destination buffer (uint8_t)
 * @param[in] src           source buffer (uint32_t)
 * @param[in] len           length to copy in byte
 * @return SCL_OK           In case of success
 * @return SCL_ERROR        In case of failure
 * @warning lenght to copy shall be a multiple of 4 bytes
 */
CRYPTO_FUNCTION int32_t copy_u32_2_u8_be(uint8_t *const dest,
                                         const uint32_t *const src, size_t len);

/**
 * @brief copy 8 bits array into unsigned 64 bits array (big endian)
 *
 * @param[out] dest         destination buffer (uint8_t)
 * @param[in] src           source buffer (uint32_t)
 * @param[in] len           length to copy in byte
 * @return SCL_OK           In case of success
 * @return SCL_ERROR        In case of failure
 * @warning lenght to copy shall be a multiple of 8 bytes
 */
CRYPTO_FUNCTION int32_t copy_u64_2_u8_be(uint8_t *const dest,
                                         const uint64_t *const src, size_t len);

/**
 * @brief memset for 64 bits word to target to speed up big numbers computation
 *
 * @param[out] array        array to memset
 * @param[in] value         value to set in the array
 * @param[in] word_size     number of 64 bits words to set
 * @warning No check on pointer value
 */
void memset_u64(uint64_t *const array, uint64_t value, size_t word_size);

/**
 * @brief memcopy for 64 bits word to target to speed up big numbers computation
 *
 * @param[out] dest          destination 64 bits words array
 * @param[in] source        source 64 bits words array
 * @param[in] word_size     number of 64 bits words to copy
 * @warning No check on pointer value
 */
void memcpy_u64(uint64_t *const dest, const uint64_t *const source,
                size_t word_size);

/**
 * @brief copy and swap the whole array
 *
 * @param[out] dest         output array
 * @param[in] source        input array
 * @param[in] length        array length
 */
void copy_swap_array(uint8_t *const dest, const uint8_t *const source,
                     size_t length);

/**
 * @brief truncate an byte array to a specified bit count
 *
 * @param array             array to truncate
 * @param array_size        array size in byte
 * @param max_bit_count     max bit count (number of bits to keep)
 */
void truncate_array(uint8_t *const array, size_t array_size,
                    size_t max_bit_count);

/** @}*/

#endif /* SCL_BACKEND_UTILS_H */
