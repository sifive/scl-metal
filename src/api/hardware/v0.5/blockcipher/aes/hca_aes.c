/******************************************************************************
 *
 * SiFive Cryptographic Library (SCL)
 *
 ******************************************************************************
 * @file hca_aes.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
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

#include <stdint.h>
#include <stdio.h>

#include <scl/scl_retdefs.h>

#include <api/hardware/v0.5/blockcipher/aes/hca_aes.h>
#include <api/hardware/hca_macro.h>
#include <api/hardware/scl_hca.h>
#include <api/blockcipher/aes/aes.h>

#include <metal/io.h>
#include <metal/machine/platform.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)
#include <api/hardware/v0.5/sifive_hca-0.5.x.h>

int32_t hca_aes_setkey(const metal_scl_t *const scl, scl_aes_key_type_t type, uint64_t *key, scl_process_t aes_process, scl_process_t aes_process)
{
    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    // set the key size
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, type,
                       HCA_REGISTER_AES_CR_KEYSZ_OFFSET,
                       HCA_REGISTER_AES_CR_KEYSZ_MASK);

    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_KEY) = key[0];
    METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_AES_KEY + sizeof(uint64_t))) =
        key[1];
    METAL_REG64(scl->hca_base,
                (METAL_SIFIVE_HCA_AES_KEY + 2 * sizeof(uint64_t))) = key[2];
    METAL_REG64(scl->hca_base,
                (METAL_SIFIVE_HCA_AES_KEY + 3 * sizeof(uint64_t))) = key[3];

    __asm__ __volatile__("fence.i"); // FENCE    

    return SCL_OK;
}

int32_t hca_aes_setiv(const metal_scl_t *const scl, uint64_t *initvec)
{
    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    // Set Init Vec
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_INITV) = initvec[0];
    METAL_REG64(scl->hca_base,
                (METAL_SIFIVE_HCA_AES_INITV + sizeof(uint64_t))) = initvec[1];

    __asm__ __volatile__("fence.i"); // FENCE    

    return SCL_OK;
}

int32_t hca_aes_cipher(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                       scl_process_t aes_process,
                       scl_endianness_t data_endianness, uint64_t data_len,
                       uint8_t *data_in, uint8_t *data_out)
{

#if __riscv_xlen == 64
    uint64_t *in64 = (uint64_t *)data_in;
    uint64_t *out64 = (uint64_t *)data_out;
    register uint64_t val;
#elif __riscv_xlen == 32
    uint32_t *in32 = (uint32_t *)data_in;
    uint32_t *out32 = (uint32_t *)data_out;
    register uint32_t val;
#endif
    uint64_t i, k;
    uint64_t NbBlocks128;

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    if (aes_mode > SCL_AES_CTR)
        return SCL_INVALID_MODE;

    // Set MODE
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, SCL_HCA_AES_MODE,
                       HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                       HCA_REGISTER_CR_IFIFOTGT_MASK);

    // Set aes_mode
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_mode,
                       HCA_REGISTER_AES_CR_MODE_OFFSET,
                       HCA_REGISTER_AES_CR_MODE_MASK);

    // Set aes_process
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_process,
                       HCA_REGISTER_AES_CR_PROCESS_OFFSET,
                       HCA_REGISTER_AES_CR_PROCESS_MASK);

    // Set endianness
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, data_endianness,
                       HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                       HCA_REGISTER_CR_ENDIANNESS_MASK);

    if (aes_mode != SCL_AES_ECB)
    {
        // Set INIT
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1,
                           HCA_REGISTER_AES_CR_INIT_OFFSET,
                           HCA_REGISTER_AES_CR_INIT_MASK);
    }

    NbBlocks128 = (data_len >> 4);

    if (data_len & 0xF)
        return SCL_NOT_YET_SUPPORTED;

    for (k = 0; k < NbBlocks128; k++)
    {
        // Wait for IFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) 
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;
#if __riscv_xlen == 64
        if ((uint64_t)data_in & 0x7)
        {
            i = k << 4;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT64(data_in, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT64(data_in, (i + 8));
        }
        else
        {
            i = k << 1;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 1];
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_in & 0x3)
        {
            i = k << 4;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, (i + 12));
        }
        else
        {
            i = k << 2;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 3];
        }
#endif /* __riscv_xlen */

        // Wait for OFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) 
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK ) ;

            // Read AES result
#if __riscv_xlen == 64
        if ((uint64_t)data_out & 0x7)
        {
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
            data_out[i + 8] = (uint8_t)val;
            data_out[i + 9] = (uint8_t)(val >> 8);
            data_out[i + 10] = (uint8_t)(val >> 16);
            data_out[i + 11] = (uint8_t)(val >> 24);
            data_out[i + 12] = (uint8_t)(val >> 32);
            data_out[i + 13] = (uint8_t)(val >> 40);
            data_out[i + 14] = (uint8_t)(val >> 48);
            data_out[i + 15] = (uint8_t)(val >> 56);
        }
        else
        {
            i = k << 1;
            out64[i] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[i + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_out & 0x3)
        {
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
            data_out[i + 8] = (uint8_t)val;
            data_out[i + 9] = (uint8_t)(val >> 8);
            data_out[i + 10] = (uint8_t)(val >> 16);
            data_out[i + 11] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 12] = (uint8_t)val;
            data_out[i + 13] = (uint8_t)(val >> 8);
            data_out[i + 14] = (uint8_t)(val >> 16);
            data_out[i + 15] = (uint8_t)(val >> 24);
        }
        else
        {
            i = k << 2;
            out32[i] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#endif /* __riscv_xlen */
    }

    return SCL_OK;
}

int32_t hca_aes_auth(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                     scl_process_t aes_process,
                     scl_endianness_t data_endianness, uint32_t auth_option,
                     uint64_t aad_byte_len, uint8_t *aad, uint64_t data_byte_len,
                     uint8_t *data_in, uint8_t *data_out, uint64_t *tag)
{
#if __riscv_xlen == 64
    uint64_t *in64 = (uint64_t *)data_in;
    uint64_t *out64 = (uint64_t *)data_out;
    uint64_t *aad64 = (uint64_t *)aad;
    register uint64_t val;
#elif __riscv_xlen == 32
    uint32_t *in32 = (uint32_t *)data_in;
    uint32_t *out32 = (uint32_t *)data_out;
    uint32_t *aad32 = (uint32_t *)aad;
    register uint32_t val;
#endif /* __riscv_xlen */
    int i,j,k;
    uint64_t NbBlocks128;
    uint64_t tmp[KEY128_NB_UINT64]                __attribute__ ((aligned (8)));

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    if ((aes_mode < SCL_AES_GCM) || (aes_mode > SCL_AES_CCM))
        return SCL_INVALID_MODE;

    // Set AES_ALEN
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_ALEN) = aad_byte_len;

    // Set AES_PLDLEN
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_PDLEN) = data_byte_len;

    // Set MODE
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, SCL_HCA_AES_MODE,
                       HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                       HCA_REGISTER_CR_IFIFOTGT_MASK);

    // Set aes_mode
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_mode,
                       HCA_REGISTER_AES_CR_MODE_OFFSET,
                       HCA_REGISTER_AES_CR_MODE_MASK);

    // Set aes_process
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_process,
                       HCA_REGISTER_AES_CR_PROCESS_OFFSET,
                       HCA_REGISTER_AES_CR_PROCESS_MASK);

    // Set endianness
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, data_endianness,
                       HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                       HCA_REGISTER_CR_ENDIANNESS_MASK);
  
    // AAD
    // Set DTYPE
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 0,
                       HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                       HCA_REGISTER_AES_CR_DTYPE_MASK);

    if (aes_mode == SCL_AES_CCM)
    {
        // Set CCMT
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, auth_option,
                           HCA_REGISTER_AES_CR_CCMT_OFFSET,
                           HCA_REGISTER_AES_CR_CCMT_MASK);
        // Set CCMQ
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, (auth_option >> 4),
                           HCA_REGISTER_AES_CR_CCMQ_OFFSET,
                           HCA_REGISTER_AES_CR_CCMQ_MASK);
    }

    NbBlocks128 = aad_byte_len >> 4;

    for (k = 0; k < NbBlocks128; k++)
    {
        // Wait for IFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) 
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;
#if __riscv_xlen == 64
        if ((uint64_t)aad & 0x7)
        {
            i = k << 4;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT64(aad, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT64(aad, (i + 8));
        }
        else
        {
            i = k << 1;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad64[i + 1];
        }
#elif __riscv_xlen == 32
        if ((uint32_t)aad & 0x3)
        {
            i = k << 4;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(aad, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(aad, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(aad, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(aad, (i + 12));
        }
        else
        {
            i = k << 2;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i + 3];
        }
#endif /* __riscv_xlen */
    }

    // AAD rest
    i = aad_byte_len & 0xF;
    if (i) 
    {
        tmp[0] = 0;
        tmp[1] = 0;
        if (i < 8) {
            for (j=0 ; j < i; j++)
            {
                if ( SCL_BIG_ENDIAN_MODE == data_endianness)
                    tmp[0] = tmp[0] << 8 + *(aad + (k << 4) + i - 1 - j);
                else
                    tmp[0] = tmp[0] << 8 + *(aad + (k << 4) + j);
            }
        } else {
            tmp[0] = GET_UNIT64(aad, (k << 4));
            i -= 8;
            if (i) {
                for (j=0 ; j < i; j++)
                {
                    if ( SCL_BIG_ENDIAN_MODE == data_endianness)
                        tmp[1] = tmp[1] << 8 + *(aad + (k << 4) + i - 1 - j);
                    else
                        tmp[1] = tmp[1] << 8 + *(aad + (k << 4) + j);
                }
            } 
        }
        // Wait for IFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) 
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;

        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[0];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[1];
    }

    // PLD
    // Set DTYPE
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1,
                       HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                       HCA_REGISTER_AES_CR_DTYPE_MASK);

    NbBlocks128 = (data_byte_len >> 4);

    for (k = 0; k < NbBlocks128; k++)
    {
        // Wait for IFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) 
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;
#if __riscv_xlen == 64
        if ((uint64_t)data_in & 0x7)
        {
            i = k << 4;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT64(data_in, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT64(data_in, (i + 8));
        }
        else
        {
            i = k << 1;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 1];
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_in & 0x3)
        {
            i = k << 4;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_UNIT32(data_in, (i + 12));
        }
        else
        {
            i = k << 2;
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 3];
        }
#endif /* __riscv_xlen */

        // Wait for OFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) 
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK ) ;
            // Read AES result
#if __riscv_xlen == 64
        if ((uint64_t)data_out & 0x7)
        {
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
            data_out[i + 8] = (uint8_t)val;
            data_out[i + 9] = (uint8_t)(val >> 8);
            data_out[i + 10] = (uint8_t)(val >> 16);
            data_out[i + 11] = (uint8_t)(val >> 24);
            data_out[i + 12] = (uint8_t)(val >> 32);
            data_out[i + 13] = (uint8_t)(val >> 40);
            data_out[i + 14] = (uint8_t)(val >> 48);
            data_out[i + 15] = (uint8_t)(val >> 56);
        }
        else
        {
            i = k << 1;
            out64[i] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[i + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_out & 0x3)
        {
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
            data_out[i + 8] = (uint8_t)val;
            data_out[i + 9] = (uint8_t)(val >> 8);
            data_out[i + 10] = (uint8_t)(val >> 16);
            data_out[i + 11] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[i + 12] = (uint8_t)val;
            data_out[i + 13] = (uint8_t)(val >> 8);
            data_out[i + 14] = (uint8_t)(val >> 16);
            data_out[i + 15] = (uint8_t)(val >> 24);
        }
        else
        {
            i = k << 2;
            out32[i] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#endif /* __riscv_xlen */
    }

    // PLD rest
    i = data_byte_len & 0xF;
    if (i) 
    {
        tmp[0] = 0;
        tmp[1] = 0;
        if (i < 8) {
            for (j=0 ; j < i; j++)
            {
                if ( SCL_BIG_ENDIAN_MODE == data_endianness)
                    tmp[0] = tmp[0] << 8 + *(data_in + (k << 4) + i - 1 - j);
                else
                    tmp[0] = tmp[0] << 8 + *(data_in + (k << 4) + j);
            }
        } else {
            tmp[0] = GET_UNIT64(data_in, (k << 4));
            i -= 8;
            if (i) {
                for (j=0 ; j < i; j++)
                {
                    if ( SCL_BIG_ENDIAN_MODE == data_endianness)
                        tmp[1] = tmp[1] << 8 + *(data_in + (k << 4) + i - 1 - j);
                    else
                        tmp[1] = tmp[1] << 8 + *(data_in + (k << 4) + j);
                }
            } 
        }
        // Wait for IFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET) 
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;

        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[0];
        METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[1];

        // Read AES result
#if __riscv_xlen == 64
        if ((uint64_t)data_out & 0x7)
        {
            j = k << 4;
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[j] = (uint8_t)val;
            data_out[j + 1] = (uint8_t)(val >> 8);
            data_out[j + 2] = (uint8_t)(val >> 16);
            data_out[j + 3] = (uint8_t)(val >> 24);
            data_out[j + 4] = (uint8_t)(val >> 32);
            data_out[j + 5] = (uint8_t)(val >> 40);
            data_out[j + 6] = (uint8_t)(val >> 48);
            data_out[j + 7] = (uint8_t)(val >> 56);
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[j + 8] = (uint8_t)val;
            data_out[j + 9] = (uint8_t)(val >> 8);
            data_out[j + 10] = (uint8_t)(val >> 16);
            data_out[j + 11] = (uint8_t)(val >> 24);
            data_out[j + 12] = (uint8_t)(val >> 32);
            data_out[j + 13] = (uint8_t)(val >> 40);
            data_out[j + 14] = (uint8_t)(val >> 48);
            data_out[j + 15] = (uint8_t)(val >> 56);
        }
        else
        {
            j = k << 1;
            out64[j] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[j + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if ((uint32_t)data_out & 0x3)
        {
            j = k << 4;
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[j] = (uint8_t)val;
            data_out[j + 1] = (uint8_t)(val >> 8);
            data_out[j + 2] = (uint8_t)(val >> 16);
            data_out[j + 3] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[j + 4] = (uint8_t)val;
            data_out[j + 5] = (uint8_t)(val >> 8);
            data_out[j + 6] = (uint8_t)(val >> 16);
            data_out[j + 7] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[j + 8] = (uint8_t)val;
            data_out[j + 9] = (uint8_t)(val >> 8);
            data_out[j + 10] = (uint8_t)(val >> 16);
            data_out[j + 11] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[j + 12] = (uint8_t)val;
            data_out[j + 13] = (uint8_t)(val >> 8);
            data_out[j + 14] = (uint8_t)(val >> 16);
            data_out[j + 15] = (uint8_t)(val >> 24);
        }
        else
        {
            j = k << 2;
            out32[j] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[j + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[j + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[j + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#endif /* __riscv_xlen */
    }

    // Wait for AESBUSY is cleared
    while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_CR) >> HCA_REGISTER_AES_CR_BUSY_OFFSET) 
            & HCA_REGISTER_AES_CR_BUSY_MASK ) ;

    // Get tag
    *tag++ = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_AUTH);
    *tag = METAL_REG64(scl->hca_base, (METAL_SIFIVE_HCA_AES_AUTH + sizeof(uint64_t)) );

    return SCL_OK;
}

#endif /* METAL_SIFIVE_HCA_VERSION */
