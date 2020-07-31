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
 * @file scl_api.h
 * @brief Low level API interface description
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _SCL_API_H
#define _SCL_API_H

#include <stdint.h>
#include <stdio.h>

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

#include <api/hash/sha.h>

/**
 * \addtogroup COMMON
 * \addtogroup API
 * \ingroup COMMON
 *  @{
 */

struct _metal_scl_struct;

typedef struct _metal_scl_struct metal_scl_t;

struct __aes_func
{
    int32_t (*setkey)(const metal_scl_t *const scl, scl_aes_key_type_t type,
                      const uint64_t *const key, scl_process_t aes_process);
    int32_t (*setiv)(const metal_scl_t *const scl,
                     const uint64_t *const initvec);
    int32_t (*cipher)(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                      scl_process_t aes_process,
                      scl_endianness_t data_endianness,
                      const uint8_t *const data_in, size_t data_len,
                      uint8_t *const data_out);
    int32_t (*auth)(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                    scl_process_t aes_process, scl_endianness_t data_endianness,
                    uint32_t auth_option, const uint8_t *const aad,
                    size_t aad_len, const uint8_t *const data_in,
                    size_t data_len, uint8_t *const data_out,
                    uint64_t *const tag);
};

/*! @brief Hash low level API entry points */
struct __hash_func
{
    /**
     * @brief Init sha context
     *
     * @param[in] scl               metal scl context
     * @param[out] ctx              sha context
     * @param[in] hash_mode         hash mode
     * @param[in] data_endianness   endianess of the input data
     * @return 0                    SUCCESS
     * @return != 0                 otherwise @see scl_errors_t
     * @warning only SCL_BIG_ENDIAN_MODE is supported
     */
    int32_t (*sha_init)(const metal_scl_t *const scl, sha_ctx_t *const ctx,
                        hash_mode_t hash_mode, endianness_t data_endianness);
    /**
     * @brief Compute intermediate hash value of the chunk of data in parameter
     *
     * @param[in] scl               metal scl context
     * @param[in,out] ctx           sha context
     * @param[in] data              data to hash
     * @param[in] data_byte_len     data length to hash
     * @return 0                    SUCCESS
     * @return != 0                 otherwise @see scl_errors_t
     */
    int32_t (*sha_core)(const metal_scl_t *const scl, sha_ctx_t *const ctx,
                        const uint8_t *const data, size_t data_byte_len);
    /**
     * @brief Compute final hash value of the concatenated block pass to
     * sha_core()
     *
     * @param[in] scl               metal scl context
     * @param[in] ctx               sha context
     * @param[out] hash             hash output buffer
     * @param[in,out] hash_len      length of the hash buffer/length of the hash
     * @return 0                    SUCCESS
     * @return != 0                 otherwise @see scl_errors_t
     */
    int32_t (*sha_finish)(const metal_scl_t *const scl, sha_ctx_t *const ctx,
                          uint8_t *const hash, size_t *const hash_len);
};

struct __trng_func
{
    int (*init)(struct _metal_scl_struct *scl);
    int (*get_data)(struct _metal_scl_struct *scl, uint32_t *data_out);
};

struct _metal_scl_struct
{
#if __riscv_xlen == 64
    const uint64_t hca_base;
#elif __riscv_xlen == 32
    const uint32_t hca_base;
#endif
    const struct __aes_func aes_func;
    const struct __hash_func hash_func;
    const struct __trng_func trng_func;
};

static __inline__ int default_aes_setkey(metal_scl_t *scl,
                                         scl_aes_key_type_t type, uint64_t *key)
{
    return SCL_ERROR;
}

static __inline__ int default_aes_setiv(metal_scl_t *scl, uint64_t *initvec)
{
    return SCL_ERROR;
}

static __inline__ int
default_aes_cipher(metal_scl_t *scl, scl_aes_mode_t aes_mode,
                   scl_process_t aes_process, scl_endianness_t data_endianness,
                   uint32_t NbBlocks128, uint8_t *data_in, uint8_t *data_out)
{
    return SCL_ERROR;
}

static __inline__ int
default_aes_auth(metal_scl_t *scl, scl_aes_mode_t aes_mode,
                 scl_process_t aes_process, scl_endianness_t data_endianness,
                 uint32_t auth_option, uint64_t aad_len, uint8_t *aad,
                 uint64_t data_len, uint8_t *data_in, uint8_t *data_out,
                 uint64_t *tag)
{
    return SCL_ERROR;
}

static __inline__ int default_sha(metal_scl_t *scl, scl_hash_mode_t hash_mode,
                                  scl_endianness_t data_endianness,
                                  uint32_t NbBlocks, uint8_t *data_in,
                                  uint8_t *data_out)
{
    return SCL_ERROR;
}

static __inline__ int default_trng_init(metal_scl_t *scl) { return SCL_ERROR; }

static __inline__ int default_trng_getdata(metal_scl_t *scl, uint32_t *data_out)
{
    return SCL_ERROR;
}

/** @}*/
#endif