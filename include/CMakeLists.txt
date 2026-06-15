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
set(CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID         7  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY         48 CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_MAC             48 CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS       3  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID     1  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG        1  CACHE STRING "")
set(CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN 2 CACHE STRING "")
set(CONFIG_LIBEDHOC_LOG_LEVEL                  3  CACHE STRING "")  # INF
set(CONFIG_LIBEDHOC_MEM_BACKEND                0  CACHE STRING "")  # STACK

set(LIBEDHOC_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
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
