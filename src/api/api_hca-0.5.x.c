/* Copyright 2020 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <metal/io.h>
#include <metal/machine/platform.h>

#include <api/scl_api.h>
#include <api/sifive_hca-0.5.x.h>

#ifndef __riscv_xlen
	#error __riscv_xlen is not defined
#endif

#if ( (__riscv_xlen != 64) && (__riscv_xlen != 32) )
    #error "Unexpected __riscv_xlen"
#endif

/* This macro enforces that the compiler will not elide the given access. */
#define __METAL_ACCESS_ONCE(x) (*(__typeof__(*x) volatile *)(x))

#define METAL_REG64(base, offset) \
   (__METAL_ACCESS_ONCE( (uint64_t *)((base) + (offset) )))
#define METAL_REG32(base, offset) \
   (__METAL_ACCESS_ONCE( (uint32_t *)((base) + (offset) )))

static __inline__ void scl_hca_setfield32(metal_scl_t *scl, 
                                        uint32_t reg, uint32_t value, 
                                        char offset, uint32_t mask) {
    METAL_REG32(scl->hca_base, reg) &= ~(mask << offset);
    METAL_REG32(scl->hca_base, reg) |= ((value & mask) << offset);
}

int scl_hca_aes_setkey(metal_scl_t *scl, 
                        scl_aes_key_size_t size, uint64_t* key) {
   // set the key size
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, size, HCA_REGISTER_AES_CR_KEYSZ_OFFSET,
                       HCA_REGISTER_AES_CR_KEYSZ_MASK);

    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_KEY) = key[0];
    METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_AES_KEY + sizeof(uint64_t))) = key[1];
    METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_AES_KEY + 2*sizeof(uint64_t))) = key[2];
    METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_AES_KEY + 3*sizeof(uint64_t))) = key[3];

    return SCL_OK;
}

int scl_hca_aes_setiv(metal_scl_t *scl, uint64_t* initvec) {
    // Set Init Vec
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_INITV) = initvec[0];
    METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_AES_INITV + sizeof(uint64_t))) = initvec[1];

    return SCL_OK;
}

int scl_hca_aes_cipher(metal_scl_t *scl, 
                    scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                    scl_hca_endianness_t data_endianness,
                    uint32_t NbBlocks128, 
                    uint64_t* data_in, uint64_t* data_out) {

#if __riscv_xlen == 32
    uint32_t    *in32 = (uint32_t *)data_in;
    uint32_t    *out32 = (uint32_t *)data_out;
#endif
    int k;

    if ( aes_mode > SCL_HCA_AES_CTR )
        return SCL_INVALID_MODE;

     // Set MODE
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_CR, SCL_HCA_AES_MODE, HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                       HCA_REGISTER_CR_IFIFOTGT_MASK);

    // Set aes_mode
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_mode, HCA_REGISTER_AES_CR_MODE_OFFSET,
                       HCA_REGISTER_AES_CR_MODE_MASK);

    // Set aes_process
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_process, HCA_REGISTER_AES_CR_PROCESS_OFFSET,
                       HCA_REGISTER_AES_CR_PROCESS_MASK);

    // Set endianness
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_CR, data_endianness, HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                       HCA_REGISTER_CR_ENDIANNESS_MASK);

    if ( aes_mode != SCL_HCA_AES_ECB ) {
        // Set INIT
        scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1, HCA_REGISTER_AES_CR_INIT_OFFSET,
                            HCA_REGISTER_AES_CR_INIT_MASK);
    }

    for(k=0; k<NbBlocks128; k++){
        // Wait for IFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) & HCA_REGISTER_CR_IFIFOFULL_MASK);
#if __riscv_xlen == 64
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*2];
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*2 + 1];
#elif __riscv_xlen == 32
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4 + 1];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4 + 2];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4 + 3];
#endif

        // Wait for OFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) & HCA_REGISTER_CR_OFIFOEMPTY_MASK);
	// Read AES result
#if __riscv_xlen == 64
    data_out[k*2] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    data_out[k*2 + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
#elif __riscv_xlen == 32
    out32[k*4]     = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    out32[k*4 + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    out32[k*4 + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    out32[k*4 + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
#endif
    }

	return SCL_OK;
}

int scl_hca_aes_auth(metal_scl_t *scl,
                    scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                    scl_hca_endianness_t data_endianness,
                    uint32_t auth_option, 
                    uint64_t aad_len, uint64_t* aad,
                    uint64_t data_len, uint64_t* data_in, 
                    uint64_t* data_out, uint64_t* tag) {
#if __riscv_xlen == 32
    uint32_t    *aad32 = (uint32_t *)aad;
    uint32_t    *in32 = (uint32_t *)data_in;
    uint32_t    *out32 = (uint32_t *)data_out;
#endif
    int k;
    uint64_t NbBlocks128;

    if ( (aes_mode < SCL_HCA_AES_GCM) || (aes_mode > SCL_HCA_AES_CCM) )
        return SCL_INVALID_MODE;

     // Set MODE
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_CR, SCL_HCA_AES_MODE, HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                       HCA_REGISTER_CR_IFIFOTGT_MASK);

    // Set aes_mode
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_mode, HCA_REGISTER_AES_CR_MODE_OFFSET,
                       HCA_REGISTER_AES_CR_MODE_MASK);

    // Set aes_process
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_process, HCA_REGISTER_AES_CR_PROCESS_OFFSET,
                       HCA_REGISTER_AES_CR_PROCESS_MASK);

    // Set endianness
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_CR, data_endianness, HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                       HCA_REGISTER_CR_ENDIANNESS_MASK);

    // Set AES_ALEN
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_ALEN) = aad_len;
    // Set AES_PLDLEN
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_PDLEN) = data_len;

    // AAD
    // Set DTYPE
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 0, HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                       HCA_REGISTER_AES_CR_DTYPE_MASK);

     if ( aes_mode == SCL_HCA_AES_CCM) {
        // Set CCMT
        scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, auth_option, HCA_REGISTER_AES_CR_CCMT_OFFSET,
                        HCA_REGISTER_AES_CR_CCMT_MASK);
        // Set CCMQ
        scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, (auth_option >> 4), HCA_REGISTER_AES_CR_CCMQ_OFFSET,
                        HCA_REGISTER_AES_CR_CCMQ_MASK);
    }

    if((aad_len & 0xF) == 0)
        NbBlocks128 = aad_len >> 4;
    else
        NbBlocks128 = (aad_len >> 4) + 1;

    for(k=0; k<NbBlocks128; k++){
        // Wait for IFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) & HCA_REGISTER_CR_IFIFOFULL_MASK);
 #if __riscv_xlen == 64
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad[k*2];
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad[k*2 + 1];
#elif __riscv_xlen == 32
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[k*4];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[k*4 + 1];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[k*4 + 2];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[k*4 + 3];
#endif
    }

    // PLD
    // Set DTYPE
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1, HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                       HCA_REGISTER_AES_CR_DTYPE_MASK);

    if((data_len & 0xF) == 0)
        NbBlocks128 = (data_len >> 4);
    else
        NbBlocks128 = (data_len >> 4) + 1;

    for(k=0; k<NbBlocks128; k++){
        // Wait for IFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) & HCA_REGISTER_CR_IFIFOFULL_MASK);
 #if __riscv_xlen == 64
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*2];
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*2 + 1];
#elif __riscv_xlen == 32
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4 + 1];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4 + 2];
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*4 + 3];
#endif

        // Wait for OFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) & HCA_REGISTER_CR_OFIFOEMPTY_MASK);
	// Read AES result
#if __riscv_xlen == 64
    data_out[k*2] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    data_out[k*2 + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
#elif __riscv_xlen == 32
    out32[k*4]     = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    out32[k*4 + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    out32[k*4 + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
    out32[k*4 + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
#endif
    }

    // Wait for AESBUSY is cleared
    while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_CR) >> HCA_REGISTER_AES_CR_BUSY_OFFSET) & HCA_REGISTER_AES_CR_BUSY_MASK);

	 // Get tag
    *tag++ = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_AUTH);
    *tag   = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_AES_AUTH + sizeof(uint64_t)));

	return SCL_OK;
}

int scl_hca_sha(metal_scl_t *scl, 
                    scl_hash_mode_t hash_mode,
                    scl_hca_endianness_t data_endianness,
                    uint32_t NbBlocks512, 
                    uint64_t* data_in, uint64_t* data_out) {
#if __riscv_xlen == 32
    uint32_t    *in32 = (uint32_t *)data_in;
    uint32_t    *out32 = (uint32_t *)data_out;
#endif
    int k;
    uint64_t tmp;

    if (NbBlocks512 == 0) {
        return SCL_INVALID_INPUT;
    }

    if( (NbBlocks512 & 0x1) && (hash_mode >= SCL_HCA_HASH_SHA384) ) {
        // nb block should be even to have 1024bits
        return SCL_INVALID_INPUT;
    }

    // Set HCA_MODE to SHA
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_CR, SCL_HCA_SHA_MODE, HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                       HCA_REGISTER_CR_IFIFOTGT_MASK);

    // Set endianness
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_CR, data_endianness, HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                       HCA_REGISTER_CR_ENDIANNESS_MASK);

    // Set SHA mode
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_SHA_CR, hash_mode, HCA_REGISTER_SHA_CR_MODE_OFFSET,
                       HCA_REGISTER_SHA_CR_MODE_MASK);

    // Init SHA
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_SHA_CR, 1, HCA_REGISTER_SHA_CR_INIT_OFFSET,
                       HCA_REGISTER_SHA_CR_INIT_MASK);

    for(int k=0; k < NbBlocks512; k++) {
        // Put data in the FIFO
        // Wait for IFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) & HCA_REGISTER_CR_IFIFOFULL_MASK);
 #if __riscv_xlen == 64
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8 + 1];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8 + 2];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8 + 3];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8 + 4];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8 + 5];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8 + 6];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[k*8 + 7];
#elif __riscv_xlen == 32
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 1];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 2];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 3];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 4];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 5];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 6];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 7];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 8];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 9];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 10];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 11];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 12];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 13];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 14];
        METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[k*16 + 15];
#endif

        if(hash_mode >= SCL_HCA_HASH_SHA384){
            // Need to have 1024bits before SHA end performing.
            if (k & 0x1) {
                // Wait for SHABUSY is cleared
                while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_SHA_CR) >> HCA_REGISTER_SHA_CR_BUSY_OFFSET) & HCA_REGISTER_SHA_CR_BUSY_MASK);
            }
        } else {
            // Wait for SHABUSY is cleared
            while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_SHA_CR) >> HCA_REGISTER_SHA_CR_BUSY_OFFSET) & HCA_REGISTER_SHA_CR_BUSY_MASK);
        }
    }

    // Read hash
	 // Get tag
    *data_out++ = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_HASH);
    *data_out++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + sizeof(uint64_t)));
    *data_out++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 2*sizeof(uint64_t)));
    tmp = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 3*sizeof(uint64_t)));

    if (hash_mode == SCL_HCA_HASH_SHA224) {
        *data_out = tmp & 0xFFFFFFFF;
        return SCL_OK;
    }
    *data_out++ = tmp;
    if (hash_mode > SCL_HCA_HASH_SHA256) {
        *data_out++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 4*sizeof(uint64_t)));
        *data_out++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 5*sizeof(uint64_t)));
    }
    if (hash_mode > SCL_HCA_HASH_SHA384) {
        *data_out++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 6*sizeof(uint64_t)));
        *data_out++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 7*sizeof(uint64_t)));
    }

	return SCL_OK;
}

int scl_hca_trng_init(metal_scl_t *scl) {

    int ret = SCL_OK;

    // Lock Trim Value
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_TRNG_TRIM, 1, HCA_REGISTER_TRNG_TRIM_LOCK_OFFSET,
                       HCA_REGISTER_TRNG_TRIM_LOCK_MASK);

    // start on-demand health test
    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_TRNG_CR, 1, HCA_REGISTER_TRNG_CR_HTSTART_OFFSET,
                       HCA_REGISTER_TRNG_CR_HTSTART_MASK);

    while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_TRNG_SR) >> HCA_REGISTER_TRNG_SR_HTR_OFFSET) & HCA_REGISTER_TRNG_SR_HTR_MASK);

	// Test Heath test status
	if( ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_TRNG_SR) >> HCA_REGISTER_TRNG_SR_HTS_OFFSET) & HCA_REGISTER_TRNG_SR_HTS_MASK) != 0) {
        ret = SCL_RNG_ERROR;
    }

	// test that all 0's are read back from TRNG_DATA during startup health test
	if( METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_TRNG_DATA) != 0) {
        ret = SCL_RNG_ERROR;
    }

    scl_hca_setfield32(scl, METAL_SIFIVE_HCA_TRNG_CR, 0, HCA_REGISTER_TRNG_CR_HTSTART_OFFSET,
                       HCA_REGISTER_TRNG_CR_HTSTART_MASK);
	return ret;
}

int scl_hca_trng_getdata(metal_scl_t *scl, 
                    uint32_t* data_out) {
    // Poll for RNDRDY bit
    while( ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_TRNG_SR) >> HCA_REGISTER_TRNG_SR_RNDRDY_OFFSET) & HCA_REGISTER_TRNG_SR_RNDRDY_MASK) == 0 );
    
    // read TRNG_DATA register
    *data_out = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_TRNG_DATA);

	return SCL_OK;
}