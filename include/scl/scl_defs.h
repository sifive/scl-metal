//SiFive Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// scl_defs.h
// contains various definitions for the cryptographic algorithms
#ifndef _SCL_DEFS_H
#define _SCL_DEFS_H

#define HCA_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

typedef enum {
    SCL_HCA_AES_MODE = 0,
    SCL_HCA_SHA_MODE = 1
} scl_hca_mode_t;

typedef enum {
    SCL_HCA_LITTLE_ENDIAN_MODE = 0,
    SCL_HCA_BIG_ENDIAN_MODE = 1
} scl_hca_endianness_t;

// symmetric-crypto encryption mode
typedef enum {
    SCL_AES_ENCRYPT = 0,
    SCL_AES_DECRYPT = 1
} scl_aes_process_t;

typedef enum {
    /*! @brief Define ECB mode */
    SCL_HCA_AES_ECB = 0,
    /*! @brief Define CBC mode */
    SCL_HCA_AES_CBC = 1,
    /*! @brief Define CFB mode */
    SCL_HCA_AES_CFB = 2,
    /*! @brief Define OFB mode */
    SCL_HCA_AES_OFB = 3,
    /*! @brief Define CTR mode */
    SCL_HCA_AES_CTR = 4,
    /*! @brief Define GCM mode */
    SCL_HCA_AES_GCM = 5,
    /*! @brief Define CCM mode */
    SCL_HCA_AES_CCM = 6
} scl_aes_mode_t;


typedef enum {
    /*! @brief Define for 128 bits key lenght */
    SCL_AES_KEY128 = 0,
    /*! @brief Define for 192 bits key lenght */
    SCL_AES_KEY192 = 1,
    /*! @brief Define for 256 bits key lenght */
    SCL_AES_KEY256 = 2,
} scl_aes_key_size_t;

typedef enum {
    /*! @brief Define SHA224 mode */
    SCL_HCA_HASH_SHA224 = 0,
    /*! @brief Define SHA256 mode */
    SCL_HCA_HASH_SHA256 = 1,
    /*! @brief Define SHA384 mode */
    SCL_HCA_HASH_SHA384 = 2,
    /*! @brief Define SHA512 mode */
    SCL_HCA_HASH_SHA512 = 3
} scl_hash_mode_t;

#endif //_SCL_DEFS_H
