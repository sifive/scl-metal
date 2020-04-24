/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * Copyright 2020 SiFive, Inc
 * SPDX-License-Identifier: MIT
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

#ifndef _SCL_API_H
#define _SCL_API_H

#include <stdint.h>
#include <stdio.h>

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

struct __metal_scl;

struct __aes_func
{
    int (*setkey)(struct __metal_scl *scl, scl_aes_key_type_t type, uint64_t *key);
    int (*setiv)(struct __metal_scl *scl, uint64_t *initvec);
    int (*cipher)(struct __metal_scl *scl, scl_aes_mode_t aes_mode,
                  scl_process_t aes_process, scl_endianness_t data_endianness,
                  uint32_t NbBlocks128, uint8_t *data_in, uint8_t *data_out);
    int (*auth)(struct __metal_scl *scl, scl_aes_mode_t aes_mode,
                scl_process_t aes_process, scl_endianness_t data_endianness,
                uint32_t auth_option, uint64_t aad_len, uint8_t *aad,
                uint64_t data_len, uint8_t *data_in, uint8_t *data_out,
                uint64_t *tag);
};

struct __hash_func
{
    int (*sha)(struct __metal_scl *scl, scl_hash_mode_t hash_mode,
               scl_endianness_t data_endianness, uint32_t NbBlocks,
               uint8_t *data_in, uint8_t *data_out);
};

struct __trng_func
{
    int (*init)(struct __metal_scl *scl);
    int (*get_data)(struct __metal_scl *scl, uint32_t *data_out);
};

typedef struct __metal_scl
{
#if __riscv_xlen == 64
    const uint64_t hca_base;
#elif __riscv_xlen == 32
    const uint32_t hca_base;
#endif
    const struct __aes_func aes_func;
    const struct __hash_func hash_func;
    const struct __trng_func trng_func;
} metal_scl_t;

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
#endif