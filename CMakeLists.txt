#------------------------------------------------------------------------------
# SiFive cryptographic library
#------------------------------------------------------------------------------

# Only for SCL, there would be too many warning for the whole Metal
enable_warnings_except (
    reserved-id-macro  # __METAL macros, etc.
    covered-switch-default  # sanity feature
    padded  # structure do not need to be size-optimized
    vla  # by design, SCL uses the stack to store (many) intermediate results
    cast-align  # clang seems not able to always check the actual alignment
    EXCEPT_DEBUG # the following warnings are disabled in all builds but DEBUG
    sizeof-array-div # this one could be fixed to increase readibility
)

enable_static_analysis ()

ADD_LIBRARY (scl
  src/api/hardware/hca_utils.c
  src/api/hardware/v0.5/blockcipher/aes/hca_aes.c
  src/api/hardware/v0.5/hash/hca_sha.c
  src/api/hardware/v0.5/hash/hca_sha224.c
  src/api/hardware/v0.5/hash/hca_sha256.c
  src/api/hardware/v0.5/hash/hca_sha384.c
  src/api/hardware/v0.5/hash/hca_sha512.c
  src/api/hardware/v0.5/hash/hca_sha_miscellaneous.c
  src/api/hardware/v0.5/random/hca_trng.c
  src/api/software/asymmetric/ecc/soft_ecc.c
  src/api/software/asymmetric/ecc/soft_ecdsa.c
  src/api/software/bignumbers/soft_bignumbers.c
  src/api/software/hash/soft_sha.c
  src/api/software/hash/soft_sha224.c
  src/api/software/hash/soft_sha256.c
  src/api/software/hash/soft_sha384.c
  src/api/software/hash/soft_sha512.c
  src/api/utils.c
  src/asymmetric/ecc/scl_ecdsa.c
  src/blockcipher/aes/scl_aes_cbc.c
  src/blockcipher/aes/scl_aes_ccm.c
  src/blockcipher/aes/scl_aes_cfb.c
  src/blockcipher/aes/scl_aes_ctr.c
  src/blockcipher/aes/scl_aes_ecb.c
  src/blockcipher/aes/scl_aes_gcm.c
  src/blockcipher/aes/scl_aes_ofb.c
  src/hash/sha/scl_sha.c
  src/scl_init.c
  src/scl_utils.c
)

# Search directories with CMakeFiles.txt files, and load them
include_subprojects ()
