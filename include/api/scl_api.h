/* Copyright 2020 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _SCL_API_H
#define _SCL_API_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <scl/scl_defs.h>
#include <scl/scl_retdefs.h>

typedef struct __metal_scl metal_scl_t;

struct __aes_func {
    int (*setkey)(metal_scl_t *scl,
                    scl_aes_key_size_t size, uint64_t* key);
    int (*setiv)(metal_scl_t *scl, uint64_t* initvec);
    int (*cipher)(metal_scl_t *scl, 
                    scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                    scl_hca_endianness_t data_endianness,
                    uint32_t NbBlocks128, 
                    uint8_t* data_in, uint8_t* data_out);
    int (*auth)(metal_scl_t *scl,
                    scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                    scl_hca_endianness_t data_endianness,
                    uint32_t auth_option, 
                    uint64_t aad_len, uint64_t* aad,
                    uint64_t data_len, uint8_t* data_in, 
                    uint8_t* data_out, uint64_t* tag);
};

struct __hash_func {
    int (*sha)(metal_scl_t *scl, 
                scl_hash_mode_t hash_mode,
                scl_hca_endianness_t data_endianness,
                uint32_t NbBlocks, 
                uint8_t* data_in, uint8_t* data_out);
};

struct __trng_func {
    int (*init)(metal_scl_t *scl);
    int (*get_data)(metal_scl_t *scl, 
                uint32_t* data_out);
};

typedef struct __metal_scl {
    const uintptr_t hca_base;
    const struct __aes_func     aes_func;
    const struct __hash_func    hash_func;
    const struct __trng_func    trng_func;
} metal_scl_t;

static __inline__ int default_aes_setkey(metal_scl_t *scl,
                                        scl_aes_key_size_t size, uint64_t* key) {
    return SCL_ERROR;
}

static __inline__ int default_aes_setiv(metal_scl_t *scl, uint64_t* initvec) {
    return SCL_ERROR;
}

static __inline__ int default_aes_cipher(metal_scl_t *scl, 
                                        scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                                        scl_hca_endianness_t data_endianness,
                                        uint32_t NbBlocks128, 
                                        uint8_t* data_in, uint8_t* data_out) {
    return SCL_ERROR;
}

static __inline__ int default_aes_auth(metal_scl_t *scl,
                                        scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                                        scl_hca_endianness_t data_endianness,
                                        uint32_t auth_option, 
                                        uint64_t aad_len, uint64_t* aad,
                                        uint64_t data_len, uint8_t* data_in, 
                                        uint8_t* data_out, uint64_t* tag) {
    return SCL_ERROR;
}

static __inline__ int default_sha(metal_scl_t *scl, 
                                    scl_hash_mode_t hash_mode,
                                    scl_hca_endianness_t data_endianness,
                                    uint32_t NbBlocks, 
                                    uint8_t* data_in, uint8_t* data_out) {
    return SCL_ERROR;
}

static __inline__ int default_trng_init(metal_scl_t *scl) {
    return SCL_ERROR;
}

static __inline__ int default_trng_getdata(metal_scl_t *scl, 
                                    uint32_t* data_out) {
    return SCL_ERROR;
}

static __inline__ void scl_hca_setfield32(metal_scl_t *scl, uint32_t reg, uint32_t value, char offset, uint32_t mask);

static __inline__ int scl_hca_aes_setkey(metal_scl_t *scl, scl_aes_key_size_t size, uint64_t* key);
static __inline__ int scl_hca_aes_setiv(metal_scl_t *scl, uint64_t* initvec);

int scl_hca_aes_cipher(metal_scl_t *scl, 
                    scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                    uint32_t NbBlocks128, 
                    scl_hca_endianness_t data_endianness, 
                    uint8_t* data_in, uint8_t* data_out);
int scl_hca_aes_auth(metal_scl_t *scl,
                    scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                    scl_hca_endianness_t data_endianness,
                    uint32_t auth_option, 
                    uint64_t aad_len, uint64_t* aad,
                    uint64_t data_len, uint8_t* data_in,
                    uint8_t* data_out, uint64_t* tag);

int scl_hca_sha(metal_scl_t *scl, 
                    scl_hash_mode_t hash_mode,
                    scl_hca_endianness_t data_endianness,
                    uint32_t NbBlocks, 
                    uint8_t* data_in, uint8_t* data_out);

int scl_hca_trng_init(metal_scl_t *scl);

int scl_hca_trng_getdata(metal_scl_t *scl, 
                    uint32_t* data_out);

#endif