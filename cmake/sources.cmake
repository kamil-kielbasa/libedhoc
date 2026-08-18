# =============================================================================
# Source and include lists for libedhoc.
#
# Single source of truth shared by the standalone build, the Zephyr build
# (zephyr/CMakeLists.txt) and the tests. All paths are absolute.
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
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_cbor_internal.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_kdf_internal.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_transcript_hash_internal.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_key_slot_internal.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_common_internal.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_connection_id_internal.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_credentials_internal.c
    ${LIBEDHOC_ROOT_DIR}/library/core/edhoc_coap.c)

# Explicit list, not file(GLOB): a glob would not re-run when a file is added or
# removed, silently desyncing the builds this file keeps in sync.
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

# Each enabled suite contributes its reference source and the crypto libraries
# that implementation needs, so both lists follow the configuration.
set(LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS "")

if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_0/edhoc_cipher_suite_0.c)
    list(APPEND LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS tfpsacrypto compact25519)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_2/edhoc_cipher_suite_2.c)
    list(APPEND LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS tfpsacrypto)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_4/edhoc_cipher_suite_4.c)
    list(APPEND LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS tfpsacrypto compact25519)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_24/edhoc_cipher_suite_24.c)
    list(APPEND LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS tfpsacrypto)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
    list(APPEND LIBEDHOC_CIPHER_SUITE_SOURCES
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_pqc_1/edhoc_cipher_suite_pqc_1.c
         ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/common/edhoc_kdf_kmac256_xkcp.c)
    list(APPEND LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS tfpsacrypto oqs xkcp)
endif()

if(LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS)
    list(REMOVE_DUPLICATES LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS)
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

# --- Fuzz targets ------------------------------------------------------------

# The harnesses select a suite through the public <edhoc/cipher_suite.h>
# getters; the fuzz preset enables cipher suite 2 only.
set(LIBEDHOC_FUZZ_CIPHER_SUITE_SOURCES
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/edhoc_cipher_suite.c
    ${LIBEDHOC_ROOT_DIR}/library/cipher_suites/cipher_suite_2/edhoc_cipher_suite_2.c)
set(LIBEDHOC_FUZZ_CIPHER_SUITE_CRYPTO_BACKENDS tfpsacrypto)
