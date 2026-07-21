# =============================================================================
# libedhoc::api — the PUBLIC interface: public headers + generated config.
# Header-only INTERFACE target. Carries NO implementation, NO backends.
# =============================================================================

add_library(libedhoc_api INTERFACE)
add_library(libedhoc::api ALIAS libedhoc_api)

# --- Generated build-time configuration header ------------------------------
# Standalone defaults. On Zephyr these values come from Kconfig (autoconf.h);
# the Zephyr build does not enter this file. CACHE so values passed on the
# command line (-DCONFIG_LIBEDHOC_*) take precedence.
set(CONFIG_LIBEDHOC_ENABLE                     1  CACHE STRING "")
set(CONFIG_LIBEDHOC_KEY_ID_LEN                 4  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES    3  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_METHODS          4  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID         7  CACHE STRING "")
# The ephemeral-key buffers are sized for the largest reference suite — the
# post-quantum suite 1 (ML-KEM-512: 800-byte public key, 768-byte ciphertext,
# 64-byte SHAKE256/KMAC MAC). The classic NIKE suites (X25519 / P-256) fit well
# within these maxima.
set(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_PUBLIC_KEY  800 CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT  768 CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_NIKE_KEY        48  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_MAC             64  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS       3  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID     1  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG        1  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN 2 CACHE STRING "")
set(CONFIG_LIBEDHOC_LOG_LEVEL                  3  CACHE STRING "")  # INF
set(CONFIG_LIBEDHOC_MEM_BACKEND                0  CACHE STRING "")  # STACK

# Reference cipher suites returned by edhoc_cipher_suite_get_*(). Disabling one
# drops its source from the build and makes the getters return NULL for it. The
# post-quantum suite additionally gates liboqs / XKCP in externals/, so include/
# is processed before dependencies.cmake (see the root CMakeLists).
set(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE      1  CACHE STRING "")
set(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE      1  CACHE STRING "")
set(CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE      1  CACHE STRING "")
set(CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE     1  CACHE STRING "")
set(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE  1  CACHE STRING "")

set(LIBEDHOC_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated
    CACHE INTERNAL "Directory holding libedhoc generated headers (edhoc_config.h)")
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/edhoc_config.h.in
    ${LIBEDHOC_GENERATED_DIR}/edhoc_config.h
    @ONLY)

# Public headers live here; the generated config sits in a build dir. Both are
# exposed on the public include path, and both map to <prefix>/include on install.
target_include_directories(libedhoc_api INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${LIBEDHOC_GENERATED_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

set_target_properties(libedhoc_api PROPERTIES EXPORT_NAME api)
