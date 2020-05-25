# SCL - SiFive Cryptographic Library
scl-metal provide a bridge between a high level of API for the cryptographic function and basic crypto operation, that could be a software implementation of cryptographic function or hardware implementation.

The current version, just implement the basic function operation connected to the HCA (Hardware Cryptographic Accelerator). It support AES (and AESMAC), SHA, TRNG.

For AES it support 

- key size: 128, 192 and 256 bits
- mode ECB, CBC, CFB, OFB and CTR
- mode CCM and GCM for AESMAC

For SHA it support

- SHA224, SHA256, SHA384 and SHA512



Support hte HCA version 0.5.x