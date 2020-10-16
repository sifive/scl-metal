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
#include <limits.h>

#include <scl/scl_retdefs.h>

#include <metal/io.h>
#include <metal/machine/platform.h>

#include <backend/api/macro.h>
#include <backend/hardware/hca_macro.h>
#include <backend/hardware/scl_hca.h>

#include <backend/api/blockcipher/aes/aes.h>

#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0, 5, 0)
#include <backend/hardware/v0.5/sifive_hca-0.5.x.h>
#include <backend/hardware/v0.5/blockcipher/aes/hca_aes.h>

typedef struct _hca_cipher_isr_data
{
    const metal_scl_t *scl;
    const uint8_t *data_in;
    size_t data_len;
    uint8_t *data_out;
    void (*callback)(int32_t);
} hca_cipher_isr_data_t;

CRYPTO_DATA static hca_cipher_isr_data_t hca_cipher_isr_data;

CRYPTO_FUNCTION static void hca_write_aes_block(const metal_scl_t *const scl, const uint8_t *const data_in)
{
    #if __riscv_xlen == 64
        if ( ! IS_ALIGNED_8_BYTES(data_in) )
        {
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_64BITS(data_in, 0);
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_64BITS(data_in, 8);
        }
        else
        {
            #pragma GCC diagnostic push
            // data_in is known to be aligned on uint64_t
            #pragma GCC diagnostic ignored "-Wcast-align"
            const uint64_t *in64 = (const uint64_t *)data_in;
            #pragma GCC diagnostic pop
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[0];
            METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in64[1];
        }
    #elif __riscv_xlen == 32
        if ( ! IS_ALIGNED_4_BYTES(data_in) )
        {
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_32BITS(data_in, 0);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_32BITS(data_in, 4);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_32BITS(data_in, 8);
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) =
                GET_32BITS(data_in, 12);
        }
        else
        {
            #pragma GCC diagnostic push
            // data_in is known to be aligned on uint32_t
            #pragma GCC diagnostic ignored "-Wcast-align"
            const uint32_t *in32 = (const uint32_t *)data_in;
            #pragma GCC diagnostic pop
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[0];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[1];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[2];
            METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = in32[3];
        }
    #endif /* __riscv_xlen */
}

CRYPTO_FUNCTION static void hca_read_aes_block(const metal_scl_t *const scl, uint8_t *const data_out)
{
    #if __riscv_xlen == 64
        if ( ! IS_ALIGNED_8_BYTES(data_out) )
        {
            register uint64_t val;

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
            #pragma GCC diagnostic push
            // data_out is known to be aligned on uint64_t
            #pragma GCC diagnostic ignored "-Wcast-align"
            uint64_t *out64 = (uint64_t *)data_out;
            #pragma GCC diagnostic pop

            out64[0] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out64[1] = METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
    #elif __riscv_xlen == 32
        if ( ! IS_ALIGNED_4_BYTES(data_out) )
        {
            register uint32_t val;

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
            #pragma GCC diagnostic push
            // data_out is known to be aligned on uint32_t
            #pragma GCC diagnostic ignored "-Wcast-align"
            uint32_t *out32 = (uint32_t *)data_out;
            #pragma GCC diagnostic pop

            out32[0] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[1] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[2] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
            out32[3] = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_OUT);
        }
    #endif /* __riscv_xlen */
}

CRYPTO_FUNCTION static void hca_cipher_dma_isr(int id, void * priv_data)
{
    hca_cipher_isr_data_t *hca_cipher_isr_data_ptr = (hca_cipher_isr_data_t *)priv_data;
    int32_t ret = SCL_OK;
    register uint32_t reg;
    
    /* Remove compiler warning about unused variables */
	( void ) id;

    if (NULL == hca_cipher_isr_data_ptr) {
        /* we can do nothing, just return */
        return;
    }

    if (NULL == hca_cipher_isr_data_ptr->scl) {
        ret = SCL_INVALID_INPUT;
        goto exit_hca_cipher_dma_isr;
    }

    /* Wait for AESBUSY is cleared (Sanity check) */
    while ( (METAL_REG32(hca_cipher_isr_data_ptr->scl->hca_base, 
                         METAL_SIFIVE_HCA_AES_CR) >> HCA_REGISTER_AES_CR_BUSY_OFFSET) 
            & HCA_REGISTER_AES_CR_BUSY_MASK ) ;

    /* Clear DMA IRQ */
    hca_setfield32(hca_cipher_isr_data_ptr->scl, METAL_SIFIVE_HCA_CR, 1,
                   HCA_REGISTER_CR_DMADIS_OFFSET,
                   HCA_REGISTER_CR_DMADIS_MASK);

    /* Disable DMA IRQ */
    hca_setfield32(hca_cipher_isr_data_ptr->scl, METAL_SIFIVE_HCA_CR, 0,
                HCA_REGISTER_CR_DMADIE_OFFSET,
                HCA_REGISTER_CR_DMADIE_MASK);

    /* Check DMA Busy */
    reg = METAL_REG32(hca_cipher_isr_data_ptr->scl->hca_base, METAL_SIFIVE_HCA_DMA_CR);
    if ( (reg >> HCA_REGISTER_DMA_CR_BUSY_OFFSET) & HCA_REGISTER_DMA_CR_BUSY_MASK )
    {
        ret = SCL_ERROR;
    }

    /* Data not treated with DMA */
    if (0 != hca_cipher_isr_data_ptr->data_len)
    {
        uint32_t i;

        for (i=0; i < hca_cipher_isr_data_ptr->data_len; i++)
        {
            METAL_REG8(hca_cipher_isr_data_ptr->scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = hca_cipher_isr_data_ptr->data_in[i];
        }
        /* we should have 16 byte in FIFO */
        /* Read AES result */
        hca_read_aes_block(hca_cipher_isr_data_ptr->scl, &hca_cipher_isr_data_ptr->data_out[0]);
    }

    reg = METAL_REG32(hca_cipher_isr_data_ptr->scl->hca_base, METAL_SIFIVE_HCA_CR);
    /* Check FIFO IN not empty */
    if ( ((reg >> HCA_REGISTER_CR_IFIFOEMPTY_OFFSET) & HCA_REGISTER_CR_IFIFOEMPTY_MASK) != HCA_REGISTER_CR_IFIFOEMPTY_MASK)
    {
        ret = SCL_ERROR;
    }

    /* Check FIFO OUT not empty */
    if ( ((reg >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) & HCA_REGISTER_CR_OFIFOEMPTY_MASK) != HCA_REGISTER_CR_OFIFOEMPTY_MASK)
    {
        ret = SCL_ERROR;
    }

exit_hca_cipher_dma_isr:    
    if (NULL != hca_cipher_isr_data_ptr->callback)
    {
        hca_cipher_isr_data_ptr->callback(ret);
    }
}

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
                       const uint8_t *const data_in, size_t data_len, 
                       uint8_t *const data_out)
{
    uint64_t k;
    uint64_t NbBlocks128;

    if (NULL == scl)
    {
        return SCL_INVALID_INPUT;
    }

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        // revision of AES is Zero so the AES is not present.
        return SCL_ERROR;
    }

    if (aes_mode > SCL_AES_CTR)
    {
        return SCL_INVALID_MODE;
    }

    if (data_len % BLOCK128_NB_BYTE)
    {
        return SCL_NOT_YET_SUPPORTED;
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

    if (aes_mode != SCL_AES_ECB)
    {
        // Set INIT
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1,
                       HCA_REGISTER_AES_CR_INIT_OFFSET,
                       HCA_REGISTER_AES_CR_INIT_MASK);
    }

    NbBlocks128 = data_len / BLOCK128_NB_BYTE;

    for (k = 0; k < NbBlocks128; k++)
    {
        /* Wait for IFIFOFULL is cleared */
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET )
                & HCA_REGISTER_CR_IFIFOFULL_MASK )
        {
            /* Put nop to avoid empty loop */
            __asm__ __volatile__ ("nop");
        }

        hca_write_aes_block(scl, &data_in[k * BLOCK128_NB_BYTE]);

        /* Wait for OFIFOEMPTY is cleared */
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET )
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK )
        {
            /* Put nop to avoid empty loop */
            __asm__ __volatile__ ("nop");
        }

        /* Read AES result */
        hca_read_aes_block(scl, &data_out[k * BLOCK128_NB_BYTE]);
    }

    return SCL_OK;
}

int32_t hca_aes_cipher_with_dma(const metal_scl_t *const scl, 
                                scl_aes_mode_t aes_mode,
                                scl_process_t aes_process,
                                scl_endianness_t data_endianness,
                                const uint8_t *const data_in, size_t data_len, 
                                uint8_t *const data_out,
                                void (*callback)(int32_t))
{
    uint64_t NbBlocks128;
    const uint8_t *dma_in = &data_in[0];

    if (NULL == scl)
    {
        return SCL_INVALID_INPUT;
    }

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        /* revision of AES is Zero so the AES is not present. */
        return SCL_ERROR;
    }

    if (aes_mode > SCL_AES_CTR)
    {
        return SCL_INVALID_MODE;
    }

    if (data_len % BLOCK128_NB_BYTE)
    {
        return SCL_NOT_YET_SUPPORTED;
    }

    /* DMA request 16 Bytes aligment for ouput */
    if ( ! IS_ALIGNED_16_BYTES(data_out) )
    {
        return SCL_INVALID_OUTPUT;
    }
    
    #if __riscv_xlen == 64
        /* verify @ of src (METAL_SIFIVE_HCA_DMA_SRC is 32bits register) */
        if ( ((uintptr_t)(data_in)) >> 32 )
        {
            return SCL_NOT_YET_SUPPORTED;
        }
        /* verify @ of dst (METAL_SIFIVE_HCA_DMA_DST is 32bits register) */
        if ( ((uintptr_t)(data_out)) >> 32 )
        {
            return SCL_NOT_YET_SUPPORTED;
        }
    #endif /* __riscv_xlen == 64 */

    NbBlocks128 = data_len / BLOCK128_NB_BYTE;

    if (0 == NbBlocks128) 
    {
        return SCL_INVALID_INPUT;
    }

    hca_cipher_isr_data.scl = scl;
    hca_cipher_isr_data.data_in = NULL;
    hca_cipher_isr_data.data_len = 0;
    hca_cipher_isr_data.data_out = NULL;
    hca_cipher_isr_data.callback = callback;


    /* DMA request 16 Bytes aligment for input */
    if ( ! IS_ALIGNED_16_BYTES(data_in) )
    {
        uint32_t i, NbBytes;
        register uint32_t reg;

        hca_cipher_isr_data.data_len = (((uintptr_t)(data_in)) & 0xfu);
        NbBytes = 0x10u - (uint32_t)hca_cipher_isr_data.data_len;
        for (i=0; i < NbBytes; i++)
        {
            METAL_REG8(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = data_in[i];
        }
        NbBlocks128--;
        dma_in = &data_in[i];
        hca_cipher_isr_data.data_in = &data_in[(NbBlocks128 * BLOCK128_NB_BYTE) + i];
        hca_cipher_isr_data.data_out = &data_out[NbBlocks128 * BLOCK128_NB_BYTE];

        reg = METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR);
        //     Check FIFO OUT not empty
        if ( ((reg >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET) & HCA_REGISTER_CR_OFIFOEMPTY_MASK) != HCA_REGISTER_CR_OFIFOEMPTY_MASK)
        {
            return SCL_INVALID_INPUT;
        }
    }

    /* DMA nb block is greater than 2^32 (METAL_SIFIVE_HCA_DMA_LEN is 32bits 
     * register) 
     */
    if ( NbBlocks128 >> 32 )
    {
        return SCL_NOT_YET_SUPPORTED;
    }

    /* Set MODE */
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, SCL_HCA_AES_MODE,
                   HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                   HCA_REGISTER_CR_IFIFOTGT_MASK);

    /* Set aes_mode */
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_mode,
                   HCA_REGISTER_AES_CR_MODE_OFFSET,
                   HCA_REGISTER_AES_CR_MODE_MASK);

    /* Set aes_process */
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_process,
                   HCA_REGISTER_AES_CR_PROCESS_OFFSET,
                   HCA_REGISTER_AES_CR_PROCESS_MASK);

    /* Set endianness */
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, data_endianness,
                   HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                   HCA_REGISTER_CR_ENDIANNESS_MASK);

    if (aes_mode != SCL_AES_ECB)
    {
        /* Set INIT */
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1,
                       HCA_REGISTER_AES_CR_INIT_OFFSET,
                       HCA_REGISTER_AES_CR_INIT_MASK);
    }

    if (NULL != callback)
    {
        /* Register Handler */
        scl->system_register_handler(scl, &hca_cipher_dma_isr, &hca_cipher_isr_data);
    }

    /* Configure DMA */
    #pragma GCC diagnostic push
    /* data_in is known to be 32bits address */
    /* data_out is known to be 32bits address */
    /* NbBlocks128 is known to be 32bits value */
    #pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
printf ("SRC = %x DST=%x LEN=%d\n", (uint32_t)dma_in, (uint32_t)data_out, (uint32_t)NbBlocks128);
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_DMA_SRC) = (uint32_t)dma_in;
    //METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_DMA_DEST) = (uint32_t)data_out;
    METAL_REG32(scl->hca_base, 0x120) = (uint32_t)data_out;
    METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_DMA_LEN)  = (uint32_t)NbBlocks128;
    #pragma GCC diagnostic pop

    /* IRQ: not on Crypto done */
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, 0,
                  HCA_REGISTER_CR_CRYPTODIE_OFFSET,
                  HCA_REGISTER_CR_CRYPTODIE_MASK);

    /* IRQ: not on output FIFO not empty */
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, 0,
                  HCA_REGISTER_CR_OFIFOIE_OFFSET,
                  HCA_REGISTER_CR_OFIFOIE_MASK);

    if (NULL != callback)
    {
        /* IRQ: on DMA done */
        hca_setfield32(scl, METAL_SIFIVE_HCA_CR, 1,
                    HCA_REGISTER_CR_DMADIE_OFFSET,
                    HCA_REGISTER_CR_DMADIE_MASK);
    }

    /* Start DMA */
    hca_setfield32(scl, METAL_SIFIVE_HCA_DMA_CR, 1,
                        HCA_REGISTER_DMA_CR_START_OFFSET,
                        HCA_REGISTER_DMA_CR_START_MASK);

    if (NULL == callback)
    {
        /* Poll on DMA_BUSY */
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_DMA_CR) >> HCA_REGISTER_DMA_CR_BUSY_OFFSET) 
                & HCA_REGISTER_DMA_CR_BUSY_MASK ) ;

        if (0 != hca_cipher_isr_data.data_len)
        {
            uint32_t i;

            for (i=0; i < hca_cipher_isr_data.data_len; i++)
            {
                METAL_REG8(scl->hca_base, METAL_SIFIVE_HCA_FIFO_IN) = hca_cipher_isr_data.data_in[i];
            }
            /* we should have 16 byte in FIFO */
            /* Read AES result */
            hca_read_aes_block(scl, &hca_cipher_isr_data.data_out[0]);
        }
    }

    return SCL_OK;
}

int32_t hca_aes_auth_init(const metal_scl_t *const scl, aes_auth_ctx_t *const ctx, scl_aes_mode_t aes_mode,
                     scl_process_t aes_process,
                     scl_endianness_t data_endianness, uint32_t auth_option,
                     const uint8_t *const aad, size_t aad_byte_len, size_t payload_len)
{
    uint32_t i, j, k;
    uint64_t NbBlocks128;
    uint64_t tmp[BLOCK128_NB_UINT64]                __attribute__ ((aligned (8)));
    uint8_t ccmt = 0;
    uint8_t ccmq = 0;

    if (0 == METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_AES_REV))
    {
        /* revision of AES is Zero so the AES is not present. */
        return SCL_ERROR;
    }

    if ((aes_mode < SCL_AES_GCM) || (aes_mode > SCL_AES_CCM)) {
        return SCL_INVALID_MODE;
    }

    /* Reset value for context */
    ctx->pld_len = payload_len;
    ctx->buf[0] = 0;
    ctx->buf[1] = 0;
    ctx->buf_len = 0;
    ctx->data_endianness = data_endianness;

    if (aes_mode == SCL_AES_CCM)
    {
        ccmt = (uint8_t)(auth_option & 0xF);
        ccmq = (uint8_t)((auth_option >> 4) & 0xF);
        /* check CCMT value */
        if ((ccmt < 1) || (ccmt > 8))
        {
            return SCL_INVALID_INPUT;
        }

        /* check CCMQ value */
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

    /* Set MODE */
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, SCL_HCA_AES_MODE,
                   HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                   HCA_REGISTER_CR_IFIFOTGT_MASK);

    /* Set aes_mode */
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_mode,
                   HCA_REGISTER_AES_CR_MODE_OFFSET,
                   HCA_REGISTER_AES_CR_MODE_MASK);

    /* Set aes_process */
    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, aes_process,
                   HCA_REGISTER_AES_CR_PROCESS_OFFSET,
                   HCA_REGISTER_AES_CR_PROCESS_MASK);

    /* Set endianness */
    hca_setfield32(scl, METAL_SIFIVE_HCA_CR, data_endianness,
                       HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                       HCA_REGISTER_CR_ENDIANNESS_MASK);

    /* Set AES_ALEN */
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_ALEN) = aad_byte_len;

    /* Set AES_PLDLEN */
    METAL_REG64(scl->hca_base, METAL_SIFIVE_HCA_AES_PDLEN) = payload_len;

    if (aes_mode == SCL_AES_CCM)
    {
        /* Set CCMT */
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, (uint32_t)ccmt,
                           HCA_REGISTER_AES_CR_CCMT_OFFSET,
                           HCA_REGISTER_AES_CR_CCMT_MASK);
        /* Set CCMQ */
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, (uint32_t)(ccmq - 1),
                           HCA_REGISTER_AES_CR_CCMQ_OFFSET,
                           HCA_REGISTER_AES_CR_CCMQ_MASK);
    }

    if (aad_byte_len)
    {
        /* AAD */
        /* Set DTYPE */
        hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 0,
                        HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                        HCA_REGISTER_AES_CR_DTYPE_MASK);

        NbBlocks128 = aad_byte_len / BLOCK128_NB_BYTE;

        for (k = 0; k < NbBlocks128; k++)
        {
            /* Wait for IFIFOFULL is cleared */
            while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET )
                    & HCA_REGISTER_CR_IFIFOFULL_MASK )
            {
                /* Put nop to avoid empty loop */
                __asm__ __volatile__ ("nop");
            }

            hca_write_aes_block(scl, &aad[k * BLOCK128_NB_BYTE]);
        }

        /* AAD rest */
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
                    tmp[1] += ((uint64_t)(*((const uint8_t *)(aad + (k * BLOCK128_NB_BYTE) + j)))) << (j * CHAR_BIT);
                }
            }
            else
            {
                tmp[1] = GET_64BITS(aad, (k * BLOCK128_NB_BYTE));

                if (i > sizeof(uint64_t))
                {
                    for (j = 0 ; j < (i - sizeof(uint64_t)); j++)
                    {
                        tmp[0] += ((uint64_t)(*((const uint8_t *)(aad + (k * BLOCK128_NB_BYTE) + sizeof(uint64_t) + j)))) << (j * CHAR_BIT);
                    }
                }
            }

            /* Wait for IFIFOFULL is cleared */
            while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET )
                    & HCA_REGISTER_CR_IFIFOFULL_MASK )
            {
                /* Put nop to avoid empty loop */
                __asm__ __volatile__ ("nop");
            }

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
                uint32_t * aad32 = (uint32_t *)tmp;

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

int32_t hca_aes_auth_core(const metal_scl_t *const scl, 
                          aes_auth_ctx_t *const ctx,
                          const uint8_t *const data_in, size_t payload_len, 
                          uint8_t *const data_out, size_t *const len_out)
{
    #if __riscv_xlen == 64
        const uint64_t *in64 = (const uint64_t *)data_in;
    #elif __riscv_xlen == 32
        const uint32_t *in32 = (const uint32_t *)data_in;
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
        /* revision of AES is Zero so the AES is not present. */
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

    /* PLD */
    /* Set DTYPE */
    /* Wait for IFIFOFULL is cleared to be sure that we do not change the type 
     * of data of previous data 
     */
    while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET)
            & HCA_REGISTER_CR_IFIFOFULL_MASK )
    {
        /* Put nop to avoid empty loop */
        __asm__ __volatile__ ("nop");
    }

    hca_setfield32(scl, METAL_SIFIVE_HCA_AES_CR, 1,
                       HCA_REGISTER_AES_CR_DTYPE_OFFSET,
                       HCA_REGISTER_AES_CR_DTYPE_MASK);

    if (0 != ctx->buf_len)
    {
        /* Fill up the previous context */
        in_offset = 0;
        if (ctx->buf_len < sizeof(uint64_t))
        {
            for (i=0 ; i < (sizeof(uint64_t) - ctx->buf_len); i++)
            {
                ctx->buf[1] += ((uint64_t)(*((const uint8_t *)(data_in + i)))) << ((ctx->buf_len + i) * CHAR_BIT);
            }
            ctx->buf_len += i;
            in_offset = i;
        }

        for (i=0 ; i < ((2*sizeof(uint64_t)) - ctx->buf_len); i++)
        {
            ctx->buf[0] += ((uint64_t)(*((const uint8_t *)(data_in + i)))) << ((ctx->buf_len - sizeof(uint64_t) + i) * CHAR_BIT);
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
            in64 = (const uint64_t *)(data_in + in_offset);
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

        /* Wait for OFIFOEMPTY is cleared */
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET)
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK )
        {
            /* Put nop to avoid empty loop */
            __asm__ __volatile__ ("nop");
        }

        /* Read output result */
        hca_read_aes_block(scl, data_out);
        out_offset = BLOCK128_NB_BYTE;
    }

    // No reming data
    NbBlocks128 = ((payload_len - in_offset) / BLOCK128_NB_BYTE);

    for (k = 0; k < NbBlocks128; k++)
    {
        // Wait for IFIFOFULL is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_IFIFOFULL_OFFSET)
                & HCA_REGISTER_CR_IFIFOFULL_MASK ) ;

        hca_write_aes_block(scl, &data_in[in_offset + (k * BLOCK128_NB_BYTE)]);

        // Wait for OFIFOEMPTY is cleared
        while ( (METAL_REG32(scl->hca_base, METAL_SIFIVE_HCA_CR) >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET)
                & HCA_REGISTER_CR_OFIFOEMPTY_MASK );

        // Read AES result
        hca_read_aes_block(scl, &data_out[out_offset]);
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
                ctx->buf[1] +=  ((uint64_t)(*((const uint8_t *)(data_in + in_offset + i)))) << (i * CHAR_BIT);
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
                    ctx->buf[0] += ((uint64_t)(*((const uint8_t *)(data_in + in_offset + i)))) << (i * CHAR_BIT);
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
