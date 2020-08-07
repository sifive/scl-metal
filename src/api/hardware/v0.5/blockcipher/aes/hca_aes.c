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
 * @file hca_aes.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>

#include <scl/scl_retdefs.h>

#include <metal/io.h>
#include <metal/machine/platform.h>

#include <api/hardware/hca_macro.h>
#include <api/hardware/scl_hca.h>

#include <api/blockcipher/aes/aes.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)
#include <api/hardware/v0.5/sifive_hca-0.5.x.h>
#include <api/hardware/v0.5/blockcipher/aes/hca_aes.h>

int32_t hca_aes_setkey(const metal_scl_t *const scl, scl_aes_key_type_t type,
                       const uint64_t *const key, scl_process_t aes_process)
{
    /* Remove compiler warning about unused parameter. */
    (void)aes_process;

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

int32_t hca_aes_setiv(const metal_scl_t *const scl, const uint64_t *const iv)
{
    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    // Set Init Vec
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_INITV) = iv[0];
    METAL_REG64(scl->hca_base,
                (METAL_SIFIVE_HCA_AES_INITV + sizeof(uint64_t))) = iv[1];

    __asm__ __volatile__("fence.i"); // FENCE

    return SCL_OK;
}

int32_t hca_aes_cipher(const metal_scl_t *const scl, scl_aes_mode_t aes_mode,
                       scl_process_t aes_process,
                       scl_endianness_t data_endianness,
                       const uint8_t *const data_in, size_t data_len, uint8_t *const data_out)
{

#if __riscv_xlen == 64
    const uint64_t *in64 = (const uint64_t *)data_in;
    uint64_t *out64 = (uint64_t *)data_out;
    register uint64_t val;
#elif __riscv_xlen == 32
    const uint32_t *in32 = (const uint32_t *)data_in;
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
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET )
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;
#if __riscv_xlen == 64
        if ((uint64_t)data_in & 0x7)
        {
            i = k << 4;
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_64BITS(data_in, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_64BITS(data_in, (i + 8));
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
                GET_32BITS(data_in, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_32BITS(data_in, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_32BITS(data_in, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_32BITS(data_in, (i + 12));
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
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET )
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

int32_t hca_aes_auth_init(const metal_scl_t *const scl, aes_auth_ctx_t *const ctx, scl_aes_mode_t aes_mode,
                     scl_process_t aes_process,
                     scl_endianness_t data_endianness, uint32_t auth_option,
                     const uint8_t *const aad, size_t aad_byte_len, uint64_t payload_len)
{
#if __riscv_xlen == 64
    const uint64_t *aad64 = (const uint64_t *)aad;
#elif __riscv_xlen == 32
    const uint32_t *aad32 = (const uint32_t *)aad;
#endif /* __riscv_xlen */
    uint32_t i, j, k;
    uint64_t NbBlocks128;
    uint64_t tmp[BLOCK128_NB_UINT64]                __attribute__ ((aligned (8)));
    uint8_t ccmt = 0;
    uint8_t ccmq = 0;

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    if ((aes_mode < SCL_AES_GCM) || (aes_mode > SCL_AES_CCM)) {
        return SCL_INVALID_MODE;
    }

    // Reset value for context
    ctx->pld_len = payload_len;
    ctx->buf[0] = 0;
    ctx->buf[1] = 0;
    ctx->buf_len = 0;
    ctx->data_endianness = data_endianness;

    if (aes_mode == SCL_AES_CCM)
    {
        ccmt = (uint8_t)(auth_option & 0xF);
        ccmq = (uint8_t)((auth_option >> 4) & 0xF);
        // check CCMT value
        if ((ccmt < 1) || (ccmt > 8))
        {
            return SCL_INVALID_INPUT;
        }

        // check CCMQ value
        if ((ccmq < 2) || (ccmq > 8))
        {
            return SCL_INVALID_INPUT;
        }

        switch (ccmq)
        {
            case 2:
                if ( payload_len >= (((uint64_t)1 << (ccmq * 8))) ) {
                    return SCL_INVALID_INPUT;
                }
                break;
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                if ( ( payload_len < (((uint64_t)1 << ((ccmq - 1) * 8))) ) || ( payload_len >= (((uint64_t)1 << (ccmq * 8))) ) ) {
                    return SCL_INVALID_INPUT;
                }
                break;
            case 8:
                if ( payload_len < (((uint64_t)1 << ((ccmq - 1) * 8))) ) {
                    return SCL_INVALID_INPUT;
                }
                break;
            default:
                return SCL_INVALID_INPUT;
        }
    }

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

    // Set AES_ALEN
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_ALEN) = aad_byte_len;

    // Set AES_PLDLEN
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_PDLEN) = payload_len;

    if (aes_mode == SCL_AES_CCM)
    {
        // Set CCMT
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, (uint32_t)ccmt,
                           HCA_REGISTER_AES_CR_CCMT_OFFSET,
                           HCA_REGISTER_AES_CR_CCMT_MASK);
        // Set CCMQ
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, (uint32_t)(ccmq - 1),
                           HCA_REGISTER_AES_CR_CCMQ_OFFSET,
                           HCA_REGISTER_AES_CR_CCMQ_MASK);
    }

    if (aad_byte_len)
    {
        // AAD
        // Set DTYPE
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 0,
                        HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                        HCA_REGISTER_AES_CR_DTYPE_MASK);

        NbBlocks128 = aad_byte_len / BLOCK128_NB_BYTE;

        for (k = 0; k < NbBlocks128; k++)
        {
            // Wait for IFIFOFULL is cleared
            while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET )
                    & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;
#if __riscv_xlen == 64
            if ((uint64_t)aad & 0x7)
            {
                /* get uint8_t index base on 128bits index */
                i = k * BLOCK128_NB_BYTE;
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                    GET_64BITS(aad, i);
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                    GET_64BITS(aad, (i + 8));
            }
            else
            {
                /* get uint64_t index base on 128bits index */
                i = k * BLOCK128_NB_UINT64;
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad64[i];
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad64[i + 1];
            }
#elif __riscv_xlen == 32
            if ((uint32_t)aad & 0x3)
            {
                /* get uint8_t index base on 128bits index */
                i = k * BLOCK128_NB_BYTE;
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                    GET_32BITS(aad, i);
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                    GET_32BITS(aad, (i + 4));
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                    GET_32BITS(aad, (i + 8));
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                    GET_32BITS(aad, (i + 12));
            }
            else
            {
                /* get uint32_t index base on 128bits index */
                i = k * BLOCK128_NB_UINT32;
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i + 1];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i + 2];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[i + 3];
            }
#endif /* __riscv_xlen */
        }

        // AAD rest
        i = aad_byte_len % BLOCK128_NB_BYTE;
        if (0 != i)
        {
            tmp[0] = 0;
            tmp[1] = 0;

            /* we take 2 uint64_t */
            if (i < sizeof(uint64_t))
            {
                for (j = 0 ; j < i; j++)
                {
                    tmp[1] += ((uint64_t)(*((const uint8_t *)(aad + (k * BLOCK128_NB_BYTE) + j)))) << (j * __CHAR_BIT__);
                }
            }
            else
            {
                tmp[1] = GET_64BITS(aad, (k * BLOCK128_NB_BYTE));

                if (i > sizeof(uint64_t))
                {
                    for (j = 0 ; j < (i - sizeof(uint64_t)); j++)
                    {
                        tmp[0] += ((uint64_t)(*((const uint8_t *)(aad + (k * BLOCK128_NB_BYTE) + sizeof(uint64_t) + j)))) << (j * __CHAR_BIT__);
                    }
                }
            }

            /* Wait for IFIFOFULL is cleared */
            while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET)
                    & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;

            /* Put 128bits to HCA_FIFO_IN */
#if __riscv_xlen == 64
            if ( SCL_LITTLE_ENDIAN_MODE == data_endianness)
            {
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[0];
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[1];
            }
            else
            {
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[1];
                METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = tmp[0];
            }
#elif __riscv_xlen == 32
            aad32 = (uint32_t *)tmp;
            if ( SCL_LITTLE_ENDIAN_MODE == data_endianness)
            {
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[0];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[1];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[2];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[3];
            }
            else
            {
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[2];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[3];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[0];
                METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = aad32[1];
            }
    #endif
        }
    }

    return SCL_OK;
}

int32_t hca_aes_auth_core(const metal_scl_t *const scl, aes_auth_ctx_t *const ctx,
                     const uint8_t *const data_in, uint64_t payload_len, uint8_t *const data_out, size_t *const len_out)
{
#if __riscv_xlen == 64
    const uint64_t *in64 = (const uint64_t *)data_in;
    uint64_t *out64 = (uint64_t *)data_out;
    register uint64_t val;
#elif __riscv_xlen == 32
    const uint32_t *in32 = (const uint32_t *)data_in;
    uint32_t *out32 = (uint32_t *)data_out;
    register uint32_t val;
#endif /* __riscv_xlen */
    size_t i, k;
    uint64_t NbBlocks128;
    size_t in_offset = 0, out_offset = 0;

    if (NULL == scl)
    {
        return SCL_INVALID_INPUT;
    }

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    if (NULL == ctx)
    {
        return SCL_INVALID_INPUT;
    }

    if (payload_len)
    {
        if (NULL == data_in)
        {
            return SCL_INVALID_INPUT;
        }

        if (NULL == data_out)
        {
            return SCL_INVALID_INPUT;
        }
    }

    if (payload_len > ctx->pld_len)
    {
        return SCL_INVALID_INPUT;
    }

    if (NULL == len_out)
    {
        return SCL_INVALID_INPUT;
    }

    *len_out = 0;

    ctx->pld_len -= payload_len;

    // PLD
    // Set DTYPE
    // Wait for IFIFOFULL is cleared to be sure that we do not change the type of data of previous data
    while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET)
            & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;

    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1,
                       HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                       HCA_REGISTER_AES_CR_DTYPE_MASK);
    if (0 != ctx->buf_len)
    {
        // Fill up the previous context
        in_offset = 0;
        if (ctx->buf_len < sizeof(uint64_t))
        {
            for (i=0 ; i < (sizeof(uint64_t) - ctx->buf_len); i++)
            {
                ctx->buf[1] += ((uint64_t)(*((const uint8_t *)(data_in + i)))) << ((ctx->buf_len + i) * __CHAR_BIT__);
            }
            ctx->buf_len += i;
            in_offset = i;
        }

        for (i=0 ; i < ((2*sizeof(uint64_t)) - ctx->buf_len); i++)
        {
            ctx->buf[0] += ((uint64_t)(*((const uint8_t *)(data_in + i)))) << ((ctx->buf_len - sizeof(uint64_t) + i) * __CHAR_BIT__);
        }
        in_offset += i;

#if __riscv_xlen == 64
        in64 = (uint64_t *)(ctx->buf);
        if ( SCL_LITTLE_ENDIAN_MODE == ctx->data_endianness)
        {
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[0];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[1];
        }
        else
        {
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[1];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[0];
        }
        in64 = (uint64_t *)(data_in + in_offset);
#elif __riscv_xlen == 32
        in32 = (uint32_t *)(ctx->buf);
        if ( SCL_LITTLE_ENDIAN_MODE == ctx->data_endianness)
        {
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[0];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[3];
        }
        else
        {
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[3];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[0];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[1];
        }
        in32 = (const uint32_t *)(data_in + in_offset);
#endif /* __riscv_xlen */

        // Wait for OFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET)
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK );

            // Read output result
#if __riscv_xlen == 64
        if (0 != (uint64_t)data_out % sizeof(uint64_t))
        {
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[0] = (uint8_t)val;
            data_out[1] = (uint8_t)(val >> 8);
            data_out[2] = (uint8_t)(val >> 16);
            data_out[3] = (uint8_t)(val >> 24);
            data_out[4] = (uint8_t)(val >> 32);
            data_out[5] = (uint8_t)(val >> 40);
            data_out[6] = (uint8_t)(val >> 48);
            data_out[7] = (uint8_t)(val >> 56);
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[8] = (uint8_t)val;
            data_out[9] = (uint8_t)(val >> 8);
            data_out[10] = (uint8_t)(val >> 16);
            data_out[11] = (uint8_t)(val >> 24);
            data_out[12] = (uint8_t)(val >> 32);
            data_out[13] = (uint8_t)(val >> 40);
            data_out[14] = (uint8_t)(val >> 48);
            data_out[15] = (uint8_t)(val >> 56);
        }
        else
        {
            out64[0] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if (0 != (uint32_t)data_out % sizeof(uint32_t))
        {
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[0] = (uint8_t)val;
            data_out[1] = (uint8_t)(val >> 8);
            data_out[2] = (uint8_t)(val >> 16);
            data_out[3] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[4] = (uint8_t)val;
            data_out[5] = (uint8_t)(val >> 8);
            data_out[6] = (uint8_t)(val >> 16);
            data_out[7] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[8] = (uint8_t)val;
            data_out[9] = (uint8_t)(val >> 8);
            data_out[10] = (uint8_t)(val >> 16);
            data_out[11] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[12] = (uint8_t)val;
            data_out[13] = (uint8_t)(val >> 8);
            data_out[14] = (uint8_t)(val >> 16);
            data_out[15] = (uint8_t)(val >> 24);
        }
        else
        {
            out32[0] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#endif /* __riscv_xlen */
        out_offset = BLOCK128_NB_BYTE;
    }

    // No reming data
    NbBlocks128 = ((payload_len - in_offset) / BLOCK128_NB_BYTE);

    for (k = 0; k < NbBlocks128; k++)
    {
        // Wait for IFIFOFULL is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET)
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;
#if __riscv_xlen == 64
        if (0 != (uint64_t)data_in % sizeof(uint64_t))
        {
            i = in_offset + (k * BLOCK128_NB_BYTE);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_64BITS(data_in, i);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_64BITS(data_in, (i + 8));
        }
        else
        {
            i = in_offset + (k * BLOCK128_NB_UINT64);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[i + 1];
        }
#elif __riscv_xlen == 32
        if (0 != (uint32_t)data_in % sizeof(uint32_t))
        {
            i =  in_offset + (k * BLOCK128_NB_BYTE);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_32BITS(data_in, i);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_32BITS(data_in, (i + 4));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_32BITS(data_in, (i + 8));
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = GET_32BITS(data_in, (i + 12));
        }
        else
        {
            i = in_offset + (k * BLOCK128_NB_UINT32);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[i + 3];
        }
#endif /* __riscv_xlen */

        // Wait for OFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET)
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK );
        // Read AES result
#if __riscv_xlen == 64
        if (0 != (uint64_t)data_out % sizeof(uint64_t))
        {
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[out_offset] = (uint8_t)val;
            data_out[out_offset + 1] = (uint8_t)(val >> 8);
            data_out[out_offset + 2] = (uint8_t)(val >> 16);
            data_out[out_offset + 3] = (uint8_t)(val >> 24);
            data_out[out_offset + 4] = (uint8_t)(val >> 32);
            data_out[out_offset + 5] = (uint8_t)(val >> 40);
            data_out[out_offset + 6] = (uint8_t)(val >> 48);
            data_out[out_offset + 7] = (uint8_t)(val >> 56);
            val = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[out_offset + 8] = (uint8_t)val;
            data_out[out_offset + 9] = (uint8_t)(val >> 8);
            data_out[out_offset + 10] = (uint8_t)(val >> 16);
            data_out[out_offset + 11] = (uint8_t)(val >> 24);
            data_out[out_offset + 12] = (uint8_t)(val >> 32);
            data_out[out_offset + 13] = (uint8_t)(val >> 40);
            data_out[out_offset + 14] = (uint8_t)(val >> 48);
            data_out[out_offset + 15] = (uint8_t)(val >> 56);
        }
        else
        {
            i = out_offset / sizeof(uint64_t);
            out64[i] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[i + 1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if (0 != (uint32_t)data_out % sizeof(uint32_t))
        {
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[out_offset] = (uint8_t)val;
            data_out[out_offset + 1] = (uint8_t)(val >> 8);
            data_out[out_offset + 2] = (uint8_t)(val >> 16);
            data_out[out_offset + 3] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[out_offset + 4] = (uint8_t)val;
            data_out[out_offset + 5] = (uint8_t)(val >> 8);
            data_out[out_offset + 6] = (uint8_t)(val >> 16);
            data_out[out_offset + 7] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[out_offset + 8] = (uint8_t)val;
            data_out[out_offset + 9] = (uint8_t)(val >> 8);
            data_out[out_offset + 10] = (uint8_t)(val >> 16);
            data_out[out_offset + 11] = (uint8_t)(val >> 24);
            val = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            data_out[out_offset + 12] = (uint8_t)val;
            data_out[out_offset + 13] = (uint8_t)(val >> 8);
            data_out[out_offset + 14] = (uint8_t)(val >> 16);
            data_out[out_offset + 15] = (uint8_t)(val >> 24);
        }
        else
        {
            i = out_offset / sizeof(uint32_t);
            out32[i] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[i + 3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#endif /* __riscv_xlen */
        out_offset += BLOCK128_NB_BYTE;
    }

    in_offset += (k * BLOCK128_NB_BYTE);

    // sanity check
    if (in_offset > payload_len)
    {
        return SCL_ERROR;
    }

    ctx->buf[0] = 0;
    ctx->buf[1] = 0;
    ctx->buf_len = payload_len - in_offset;

    // check rest
    if (in_offset < payload_len)
    {
        if (ctx->buf_len < sizeof(uint64_t))
        {
            for (i = 0; i < ctx->buf_len; i++)
            {
                ctx->buf[1] +=  ((uint64_t)(*((const uint8_t *)(data_in + in_offset + i)))) << (i * __CHAR_BIT__);
            }
        }
        else
        {
            ctx->buf[1] = GET_64BITS(data_in, in_offset);
            in_offset += sizeof(uint64_t);

            if (ctx->buf_len > sizeof(uint64_t))
            {
                for (i=0 ; i < (ctx->buf_len - sizeof(uint64_t)); i++)
                {
                    ctx->buf[0] += ((uint64_t)(*((const uint8_t *)(data_in + in_offset + i)))) << (i * __CHAR_BIT__);
                }
            }
        }
    }

    *len_out = out_offset;

    return SCL_OK;
}

int32_t hca_aes_auth_finish(const metal_scl_t *const scl,
                            aes_auth_ctx_t *const ctx, uint8_t *const data_out,
                            uint64_t *const tag)
{
#if __riscv_xlen == 64
    uint64_t *in64 = (uint64_t *)(ctx->buf);
    uint64_t *out64 = (uint64_t *)(ctx->buf);
#elif __riscv_xlen == 32
    uint32_t *in32 = (uint32_t *)(ctx->buf);
    uint32_t *out32 = (uint32_t *)(ctx->buf);
#endif /* __riscv_xlen */
    uint8_t *tmp = (uint8_t *)(ctx->buf);
    size_t i;

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    if (0 != ctx->buf_len)
    {
        if (NULL == data_out)
        {
            return SCL_INVALID_INPUT;
        }
#if __riscv_xlen == 64
        if ( SCL_LITTLE_ENDIAN_MODE == ctx->data_endianness)
        {
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[0];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[1];
        }
        else
        {
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[1];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[0];
        }
#elif __riscv_xlen == 32
        if ( SCL_LITTLE_ENDIAN_MODE == ctx->data_endianness)
        {
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[0];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[3];
        }
        else
        {
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[3];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[0];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[1];
        }
#endif /* __riscv_xlen */

        // Wait for OFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET)
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK );

        // use ctx->buf for the output result
        ctx->buf[0] = 0;
        ctx->buf[1] = 0;

        // Read output result
#if __riscv_xlen == 64
        if ( SCL_LITTLE_ENDIAN_MODE == ctx->data_endianness)
        {
            out64[1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[0] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
        else
        {
            out64[0] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#elif __riscv_xlen == 32
        if ( SCL_LITTLE_ENDIAN_MODE == ctx->data_endianness)
        {
            out32[2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[0] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
        else
        {
            out32[0] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
#endif /* __riscv_xlen */

        // Copy result to output
        for (i = 0; i< ctx->buf_len; i++)
        {
            data_out[i] = tmp[i];
        }

    }

    // Wait for AESBUSY is cleared
    while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_CR) >> HCA_REGISTER_AES_CR_BUSY_OFFSET)
            & HCA_REGISTER_AES_CR_BUSY_MASK ) ;

   // Get tag
    tag[0] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_AUTH);
    tag[1] = METAL_REG64(scl->hca_base,
                         (METAL_SIFIVE_HCA_AES_AUTH + sizeof(uint64_t)));

    ctx->pld_len = 0;
    ctx->buf[0] = 0;
    ctx->buf[1] = 0;

    return SCL_OK;
}
#endif /* METAL_SIFIVE_HCA_VERSION */
