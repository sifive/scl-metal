#------------------------------------------------------------------------------
# SiFive cryptographic library unit tests
#------------------------------------------------------------------------------

# remove this once Unity RUN_* macros use proper do { ... } while (0) idiom
ADD_DEFINITIONS (-Wno-extra-semi-stmt)

# build a static library with all the tests
#  this enables running the static analyzer on all the test files, w/o to try
#  to produce an executable
ADD_LIBRARY (scl-tests
  src/test_runners/test_utils_runner.c
  src/test_runners/asymmetric/test_scl_ecdsa_runner.c
  src/test_runners/asymmetric/test_scl_ecc_keygen_runner.c
  src/test_runners/asymmetric/test_scl_ecdh_runner.c
  src/test_runners/blockcipher/test_scl_aes_runner.c
  src/test_runners/selftests/test_scl_selftests_runner.c
  src/test_runners/message_auth/test_scl_hmac_runner.c
  src/test_runners/key_derivation_functions/test_scl_kdf_runner.c
  src/test_runners/backend/hardware/test_hca_sha_runner.c
  src/test_runners/backend/hardware/test_hca_aes_runner.c
  src/test_runners/hash/test_scl_sha_runner.c
  src/test_runners/backend/software/test_soft_sha_runner.c
  src/test_runners/backend/software/test_soft_hmac_runner.c
  src/test_runners/backend/software/test_soft_x963kdf_runner.c
  src/test_runners/backend/software/test_soft_ecdsa_runner.c
  src/test_runners/backend/software/test_soft_ecdh_runner.c
  src/test_runners/backend/software/test_soft_ecc_runner.c
  src/test_runners/backend/software/test_soft_ecc_keygen_runner.c
  src/test_runners/backend/software/test_soft_bignumbers_runner.c
  src/backend/hardware/blockcipher/aes/test_hca_aes_256.c
  src/backend/hardware/blockcipher/aes/test_hca_aes_192.c
  src/backend/hardware/blockcipher/aes/test_hca_aes_128.c
  src/backend/hardware/hash/sha/test_hca_sha_512.c
  src/backend/hardware/hash/sha/test_hca_sha_384.c
  src/backend/hardware/hash/sha/test_hca_sha_256.c
  src/backend/hardware/hash/sha/test_hca_sha_224.c
  src/backend/software/asymmetric/ecc/test_soft_ecdsa.c
  src/backend/software/asymmetric/ecc/test_soft_ecdh.c
  src/backend/software/asymmetric/ecc/test_soft_ecc.c
  src/backend/software/asymmetric/ecc/test_soft_ecc_keygen.c
  src/backend/software/bignumbers/test_soft_bignumbers.c
  src/backend/software/hash/sha/test_soft_sha_512.c
  src/backend/software/hash/sha/test_soft_sha_384.c
  src/backend/software/hash/sha/test_soft_sha_256.c
  src/backend/software/hash/sha/test_soft_sha_224.c
  src/backend/software/message_auth/test_soft_hmac.c
  src/backend/software/key_derivation_functions/test_soft_x963kdf.c
  src/blockcipher/aes/test_scl_aes_256.c
  src/blockcipher/aes/test_scl_aes_192.c
  src/blockcipher/aes/test_scl_aes_128.c
  src/asymmetric/ecc/test_scl_ecdsa.c
  src/asymmetric/ecc/test_scl_ecdh.c
  src/asymmetric/ecc/test_scl_ecc_keygen.c
  src/hash/sha/test_scl_sha_512.c
  src/hash/sha/test_scl_sha_384.c
  src/hash/sha/test_scl_sha_256.c
  src/hash/sha/test_scl_sha_224.c
  src/selftests/test_scl_selftests.c
  src/key_derivation_functions/test_scl_kdf.c
  src/message_auth/test_scl_hmac.c
  src/test_utils.c
)

IF (NOT DEFINED STATIC_ANALYSIS)
  SET (app test-scl-metal)

  ADD_EXECUTABLE (${app}
    src/test-scl-metal.c
  )

  link_application (${app} metal.ld scl scl-tests)

  create_map_file(${app})
  # generate artifacts: de-assembled binary and report the binary size info
  post_gen_app(${app} ASM SIZE)
ENDIF ()
