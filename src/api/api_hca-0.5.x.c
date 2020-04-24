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

#define METAL_REG64(base, offset) \
   (__METAL_ACCESS_ONCE( (uint64_t *)((base) + (offset) )))
#define METAL_REG32(base, offset) \
   (__METAL_ACCESS_ONCE( (uint32_t *)((base) + (offset) )))

#define GET_UNIT32(data, k)     ( (*(data + k + 3) << 24) + (*(data + k + 2) << 16) + (*(data + k + 1) << 8) + (*(data + k)) )
#define GET_UNIT64(data, k)     ( (((uint64_t)GET_UNIT32(data, (k+4))) << 32) + (uint64_t)GET_UNIT32(data, k) )

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
                    uint8_t* data_in, uint8_t* data_out) {

#if __riscv_xlen == 64
    uint64_t    *in64 = (uint64_t *)data_in;
    uint64_t    *out64 = (uint64_t *)data_out;
    register uint64_t    val;
#elif __riscv_xlen == 32
    uint32_t    *in32 = (uint32_t *)data_in;
    uint32_t    *out32 = (uint32_t *)data_out;
    register uint32_t    val;
#endif
    int k;
    register int i;

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
        if ((uint64_t)data_in & 0x7) {
            i = k << 4;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 8));
        } else {
            i = k << 1;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 1];
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_in & 0x3)
        {
            i = k << 4;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 12));
        } else {
            i = k << 2;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 3];
        }
#endif

        // Wait for OFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) & HCA_REGISTER_CR_OFIFOEMPTY_MASK);

    	// Read AES result
#if __riscv_xlen == 64
        if ((uint64_t)data_out & 0x7) {
            i = k << 4;
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i] = (uint8_t)val; 
            data_out[i + 1] = (uint8_t)(val >> 8); 
            data_out[i + 2] = (uint8_t)(val >> 16); 
            data_out[i + 3] = (uint8_t)(val >> 24); 
            data_out[i + 4] = (uint8_t)(val >> 32); 
            data_out[i + 5] = (uint8_t)(val >> 40); 
            data_out[i + 6] = (uint8_t)(val >> 48); 
            data_out[i + 7] = (uint8_t)(val >> 56); 
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 8]  = (uint8_t)val; 
            data_out[i + 9]  = (uint8_t)(val >> 8); 
            data_out[i + 10] = (uint8_t)(val >> 16); 
            data_out[i + 11] = (uint8_t)(val >> 24); 
            data_out[i + 12] = (uint8_t)(val >> 32); 
            data_out[i + 13] = (uint8_t)(val >> 40); 
            data_out[i + 14] = (uint8_t)(val >> 48); 
            data_out[i + 15] = (uint8_t)(val >> 56); 
        } else {
            i = k << 1;
            out64[i] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[i + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_out & 0x3) {
            i = k << 4;
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i] = (uint8_t)val; 
            data_out[i + 1] = (uint8_t)(val >> 8); 
            data_out[i + 2] = (uint8_t)(val >> 16); 
            data_out[i + 3] = (uint8_t)(val >> 24); 
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 4] = (uint8_t)val; 
            data_out[i + 5] = (uint8_t)(val >> 8); 
            data_out[i + 6] = (uint8_t)(val >> 16); 
            data_out[i + 7] = (uint8_t)(val >> 24); 
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 8]  = (uint8_t)val; 
            data_out[i + 9]  = (uint8_t)(val >> 8); 
            data_out[i + 10] = (uint8_t)(val >> 16); 
            data_out[i + 11] = (uint8_t)(val >> 24); 
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 12] = (uint8_t)val; 
            data_out[i + 13] = (uint8_t)(val >> 8); 
            data_out[i + 14] = (uint8_t)(val >> 16); 
            data_out[i + 15] = (uint8_t)(val >> 24); 

        } else {
            i = k << 2;
            out32[i]     = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#endif
    }

	return SCL_OK;
}

int scl_hca_aes_auth(metal_scl_t *scl,
                    scl_aes_mode_t aes_mode, scl_aes_process_t aes_process, 
                    scl_hca_endianness_t data_endianness,
                    uint32_t auth_option, 
                    uint64_t aad_len, uint64_t* aad,
                    uint64_t data_len, uint8_t* data_in, 
                    uint8_t* data_out, uint64_t* tag) {
#if __riscv_xlen == 64
    uint64_t    *in64 = (uint64_t *)data_in;
    uint64_t    *out64 = (uint64_t *)data_out;
    uint64_t    *aad64 = (uint32_t *)aad;
    register uint64_t    val;
#elif __riscv_xlen == 32
    uint32_t    *in32 = (uint32_t *)data_in;
    uint32_t    *out32 = (uint32_t *)data_out;
    uint32_t    *aad32 = (uint32_t *)aad;
    register uint32_t    val;
#endif
    int k;
    register int i;
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
        if ((uint64_t)aad & 0x7) {
            i = k << 4;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(aad, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(aad, (i + 8));
        } else {
            i = k << 1;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad64[i + 1];
        }
#elif __riscv_xlen == 32
        if ((uint32_t)aad & 0x3) {
            i = k << 4;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(aad, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(aad, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(aad, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(aad, (i + 12));
        } else {
            i = k << 2;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = add32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = add32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = add32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = add32[i + 3];
        }
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
        if ((uint64_t)data_in & 0x7) {
            i = k << 4;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 8));
        } else {
            i = k << 1;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 1];
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_in & 0x3) {
            i = k << 4;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 12));
        } else {
            i = k << 2;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 3];
        }
#endif

        // Wait for OFIFOEMPTY is cleared
        while ((METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) & HCA_REGISTER_CR_OFIFOEMPTY_MASK);
	// Read AES result
#if __riscv_xlen == 64
        if ((uint64_t)data_out & 0x7) {
            i = k << 4;
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i] = (uint8_t)val; 
            data_out[i + 1] = (uint8_t)(val >> 8); 
            data_out[i + 2] = (uint8_t)(val >> 16); 
            data_out[i + 3] = (uint8_t)(val >> 24); 
            data_out[i + 4] = (uint8_t)(val >> 32); 
            data_out[i + 5] = (uint8_t)(val >> 40); 
            data_out[i + 6] = (uint8_t)(val >> 48); 
            data_out[i + 7] = (uint8_t)(val >> 56); 
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 8]  = (uint8_t)val; 
            data_out[i + 9]  = (uint8_t)(val >> 8); 
            data_out[i + 10] = (uint8_t)(val >> 16); 
            data_out[i + 11] = (uint8_t)(val >> 24); 
            data_out[i + 12] = (uint8_t)(val >> 32); 
            data_out[i + 13] = (uint8_t)(val >> 40); 
            data_out[i + 14] = (uint8_t)(val >> 48); 
            data_out[i + 15] = (uint8_t)(val >> 56); 
        } else {
            i = k << 1;
            out64[i] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[i + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_out & 0x3) {
            i = k << 4;
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i] = (uint8_t)val; 
            data_out[i + 1] = (uint8_t)(val >> 8); 
            data_out[i + 2] = (uint8_t)(val >> 16); 
            data_out[i + 3] = (uint8_t)(val >> 24); 
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 4] = (uint8_t)val; 
            data_out[i + 5] = (uint8_t)(val >> 8); 
            data_out[i + 6] = (uint8_t)(val >> 16); 
            data_out[i + 7] = (uint8_t)(val >> 24); 
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 8]  = (uint8_t)val; 
            data_out[i + 9]  = (uint8_t)(val >> 8); 
            data_out[i + 10] = (uint8_t)(val >> 16); 
            data_out[i + 11] = (uint8_t)(val >> 24); 
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 12] = (uint8_t)val; 
            data_out[i + 13] = (uint8_t)(val >> 8); 
            data_out[i + 14] = (uint8_t)(val >> 16); 
            data_out[i + 15] = (uint8_t)(val >> 24); 

        } else {
            i = k << 2;
            out32[i]     = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
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
                    uint8_t* data_in, uint8_t* data_out) {
#if __riscv_xlen == 64
    uint64_t    *in64 = (uint64_t *)data_in;
#elif __riscv_xlen == 32
    uint32_t    *in32 = (uint32_t *)data_in;
#endif
    uint64_t    *out64 = (uint64_t *)data_out;
    register uint64_t    val;
    int k;
    register int i;

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
        if ((uint64_t)data_in & 0x7) {
            i = k << 6;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 8));
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 16));
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 24));
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 32));
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 40));
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 48));
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT64(data_in, (i + 56));
        } else {
            i = k << 3;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 1];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 2];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 3];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 4];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 5];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 6];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 7];
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_in & 0x3) {
            i = k << 6;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 12));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 16));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 20));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 24));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 28));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 32));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 36));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 40));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 44));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 48));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 52));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 56));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_UNIT32(data_in, (i + 60));
        } else {
            i = k << 4;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 3];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 4];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 5];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 6];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 7];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 8];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 9];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 10];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 11];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 12];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 13];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 14];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 15];
        }
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
    if ((uint32_t)data_out & 0x7) {
        val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_HASH);
        data_out[0] = (uint8_t)val; 
        data_out[1] = (uint8_t)(val >> 8); 
        data_out[2] = (uint8_t)(val >> 16); 
        data_out[3] = (uint8_t)(val >> 24); 
        val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + sizeof(uint64_t)));
        data_out[4] = (uint8_t)val; 
        data_out[5] = (uint8_t)(val >> 8); 
        data_out[6] = (uint8_t)(val >> 16); 
        data_out[7] = (uint8_t)(val >> 24); 
        val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 2*sizeof(uint64_t)));
        data_out[8] = (uint8_t)val; 
        data_out[9] = (uint8_t)(val >> 8); 
        data_out[10] = (uint8_t)(val >> 16); 
        data_out[11] = (uint8_t)(val >> 24); 
        val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 3*sizeof(uint64_t)));

        if (hash_mode == SCL_HCA_HASH_SHA224) {
            data_out[12] = (uint8_t)val; 
            data_out[13] = (uint8_t)(val >> 8); 
            return SCL_OK;
        }
        data_out[14] = (uint8_t)(val >> 16); 
        data_out[15] = (uint8_t)(val >> 24); 
        if (hash_mode > SCL_HCA_HASH_SHA256) {
            val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 4*sizeof(uint64_t)));
            data_out[16] = (uint8_t)val; 
            data_out[17] = (uint8_t)(val >> 8); 
            data_out[18] = (uint8_t)(val >> 16); 
            data_out[19] = (uint8_t)(val >> 24); 
            val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 5*sizeof(uint64_t)));
            data_out[20] = (uint8_t)val; 
            data_out[21] = (uint8_t)(val >> 8); 
            data_out[22] = (uint8_t)(val >> 16); 
            data_out[23] = (uint8_t)(val >> 24); 
        }
        if (hash_mode > SCL_HCA_HASH_SHA384) {
            val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 6*sizeof(uint64_t)));
            data_out[24] = (uint8_t)val; 
            data_out[25] = (uint8_t)(val >> 8); 
            data_out[26] = (uint8_t)(val >> 16); 
            data_out[27] = (uint8_t)(val >> 24); 
            val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 7*sizeof(uint64_t)));
            data_out[28] = (uint8_t)val; 
            data_out[29] = (uint8_t)(val >> 8); 
            data_out[30] = (uint8_t)(val >> 16); 
            data_out[31] = (uint8_t)(val >> 24); 
        }
    } else {
        *out64++ = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_HASH);
        *out64++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + sizeof(uint64_t)));
        *out64++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 2*sizeof(uint64_t)));
        val = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 3*sizeof(uint64_t)));

        if (hash_mode == SCL_HCA_HASH_SHA224) {
            *out64 = val & 0xFFFFFFFF;
            return SCL_OK;
        }
        *out64++ = val;
        if (hash_mode > SCL_HCA_HASH_SHA256) {
            *out64++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 4*sizeof(uint64_t)));
            *out64++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 5*sizeof(uint64_t)));
        }
        if (hash_mode > SCL_HCA_HASH_SHA384) {
            *out64++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 6*sizeof(uint64_t)));
            *out64++ = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_HASH + 7*sizeof(uint64_t)));
        }
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