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
  src/test_runners/test_hca_aes_runner.c
  src/test_runners/test_hca_sha_runner.c
  src/test_runners/test_scl_aes_runner.c
  src/test_runners/test_scl_ecdsa_runner.c
  src/test_runners/test_scl_sha_runner.c
  src/test_runners/test_soft_bignumbers_runner.c
  src/test_runners/test_soft_ecc_runner.c
  src/test_runners/test_soft_ecdsa_runner.c
  src/test_runners/test_soft_sha_runner.c
  src/api/aes/hardware/test_hca_aes_128.c
  src/api/aes/hardware/test_hca_aes_192.c
  src/api/aes/hardware/test_hca_aes_256.c
  src/api/asymmetric/ecc/software/test_soft_ecc.c
  src/api/asymmetric/ecc/software/test_soft_ecdsa.c
  src/api/bignumbers/software/test_soft_bignumbers.c
  src/api/sha/hardware/test_hca_sha_224.c
  src/api/sha/hardware/test_hca_sha_256.c
  src/api/sha/hardware/test_hca_sha_384.c
  src/api/sha/hardware/test_hca_sha_512.c
  src/api/sha/software/test_soft_sha_224.c
  src/api/sha/software/test_soft_sha_256.c
  src/api/sha/software/test_soft_sha_384.c
  src/api/sha/software/test_soft_sha_512.c
  src/api/test_utils.c
  src/scl/aes/test_scl_aes_128.c
  src/scl/aes/test_scl_aes_192.c
  src/scl/aes/test_scl_aes_256.c
  src/scl/asymmetric/ecc/test_scl_ecdsa.c
  src/scl/sha/test_scl_sha_224.c
  src/scl/sha/test_scl_sha_256.c
  src/scl/sha/test_scl_sha_384.c
  src/scl/sha/test_scl_sha_512.c
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