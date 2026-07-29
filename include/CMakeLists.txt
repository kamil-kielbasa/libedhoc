# =============================================================================
# libedhoc::api — public headers plus the generated configuration header.
# Header-only INTERFACE target; carries no implementation and no backends.
# =============================================================================

add_library(libedhoc_api INTERFACE)
add_library(libedhoc::api ALIAS libedhoc_api)

# --- Build-time configuration ------------------------------------------------

# Defaults for the standalone build; the Zephyr build takes these from Kconfig.
# CACHE so -DCONFIG_LIBEDHOC_* on the command line wins.
set(CONFIG_LIBEDHOC_ENABLE                     1  CACHE STRING "")
set(CONFIG_LIBEDHOC_KEY_ID_LEN                 4  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES    3  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_METHODS          4  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID         7  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY  800 CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT  768 CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_NIKE_KEY        48  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_MAC             64  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS       3  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID     1  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG        1  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN 2 CACHE STRING "")
set(CONFIG_LIBEDHOC_LOG_LEVEL                  3  CACHE STRING "")  # INF
set(CONFIG_LIBEDHOC_MEM_BACKEND                0  CACHE STRING "")  # STACK
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

# --- Usage requirements ------------------------------------------------------

# Public headers and the generated config both map to <prefix>/include on install.
target_include_directories(libedhoc_api INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${LIBEDHOC_GENERATED_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

set_target_properties(libedhoc_api PROPERTIES EXPORT_NAME api)
