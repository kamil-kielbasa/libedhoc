# =============================================================================
# Single source of truth for source and include lists, shared by:
#   * the standalone build: library/, library/cipher_suites/, backends/ CMakeLists.txt
#   * the Zephyr build:     zephyr/CMakeLists.txt
#   * tests and samples:    tests/, tests/fuzz/, sample/benchmark/
# Keeping one list keeps both builds in sync.
# All paths are absolute (CMAKE_CURRENT_LIST_DIR is this file's directory).
# =============================================================================

set(LIBEDHOC_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

set(LIBEDHOC_CORE_SOURCES
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_message_1.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_message_2.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_message_3.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_message_4.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_message_error.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_exporter.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_common.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_coap.c)

# Explicit list (not file(GLOB)): a glob would not re-run when a file is
# added/removed, which silently desyncs the two build paths this file exists
# to keep in sync.
set(LIBEDHOC_BACKEND_CBOR_SOURCES
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_bstr_type_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_bstr_type_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_connection_identifier_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_connection_identifier_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_ead_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_ead_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_enc_structure_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_enc_structure_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_id_cred_x_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_id_cred_x_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_info_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_info_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_int_type_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_int_type_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_1_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_1_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_2_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_2_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_3_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_3_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_4_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_4_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_error_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_message_error_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_plaintext_2_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_plaintext_2_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_plaintext_3_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_plaintext_3_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_plaintext_4_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_plaintext_4_encode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_sig_structure_decode.c
    ${LIBEDHOC_ROOT_DIR}/backends/cbor/src/backend_cbor_sig_structure_encode.c)

set(LIBEDHOC_CIPHER_SUITE_SOURCES
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/edhoc_cipher_suite.c)

if (CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_0/edhoc_cipher_suite_0.c)
endif()
if (CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_2/edhoc_cipher_suite_2.c)
endif()
if (CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_4/edhoc_cipher_suite_4.c)
endif()
if (CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_24/edhoc_cipher_suite_24.c)
endif()

if (LIBEDHOC_ENABLE_EXPERIMENTAL_PQC)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_pqc_1/edhoc_exp_pqc_cipher_suite_1.c
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/common/edhoc_kdf_kmac256_xkcp.c)
endif()

set(LIBEDHOC_PUBLIC_INCLUDE_DIR       ${LIBEDHOC_ROOT_DIR}/include)
set(LIBEDHOC_INTERNAL_INCLUDE_DIR     ${LIBEDHOC_ROOT_DIR}/library/internal)
set(LIBEDHOC_CIPHER_SUITE_INCLUDE_DIRS
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_0
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_2
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_4
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_24
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_pqc_1
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/common)
set(LIBEDHOC_BACKEND_CBOR_INCLUDE_DIR ${LIBEDHOC_ROOT_DIR}/backends/cbor/include)
set(LIBEDHOC_BACKEND_MEM_INCLUDE_DIR  ${LIBEDHOC_ROOT_DIR}/backends/memory/include)
set(LIBEDHOC_BACKEND_LOG_INCLUDE_DIR  ${LIBEDHOC_ROOT_DIR}/backends/log/include)

# --- Test and sample sources -------------------------------------------------

set(LIBEDHOC_TESTS_DIR ${LIBEDHOC_ROOT_DIR}/tests)

set(LIBEDHOC_TEST_COMMON_SOURCES
    ${LIBEDHOC_TESTS_DIR}/common/src/test_ead.c
    ${LIBEDHOC_TESTS_DIR}/common/src/test_credentials.c)

# Fuzz compiles a subset of the cipher-suite reference sources (no suite 24).
set(LIBEDHOC_FUZZ_CIPHER_SUITE_SOURCES
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_0/edhoc_cipher_suite_0.c
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_2/edhoc_cipher_suite_2.c)

# Zephyr benchmark sample: cipher suite 2 reference source.
set(LIBEDHOC_BENCHMARK_CIPHER_SUITE_SOURCES
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_2/edhoc_cipher_suite_2.c)
