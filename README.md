# SCL - SiFive Cryptographic Library
scl-metal provides a bridge between a high level API for the cryptographic functions and basic crypto operations, that could be either a software or a hardware implementation of cryptographic functions 

The current version implements the basic functions operations connected to the HCA (Hardware Cryptographic Accelerator). It supports the AES through the HCA-supported modes of operation, the SHA-2 and the TRNG.

For AES it supports:

- key size: 128, 192 and 256 bits
- mode ECB, CBC, CFB, OFB, CTR, CCM and GCM

For SHA-2, it supports:

- SHA224, SHA256, SHA384 and SHA512

Supports the HCA version 0.5.x

ECDSA signature and verification are supported:
    - for standard curves SECP256r1, SECP384r1 and SECP521r1

## Warning:
Local variable cleaning is not done yet, therefore it's not secure to use the library for cryptographic signature, but it's safe to use signature verification.
A cleaning mechanism will be added in the future.

## Optimization
Computation speed can be improved by placing **crypto_const_data** section/symbol into RAM. This avoid Flash access and speed up computation (on ecdsa).
Placing crypto_const_data in RAM should be done with special care (Security issues if constant are modified). Reserving a non writable/executable section protected by PMP might be a good idea.
This is only an improvment if the rodata are located in Flash.
