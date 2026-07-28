# SPDX-License-Identifier: MIT
#
# Build compact25519 (Ed25519 / X25519) as a Zephyr companion library for the
# libedhoc classic cipher suites 0 and 4, which use it for Ed25519 signatures
# (X25519 itself comes from PSA). compact25519 has no upstream Zephyr module, so
# libedhoc builds it here, mirroring cmake/xkcp_zephyr.cmake for XKCP.
#
# Included from zephyr/CMakeLists.txt when
# CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE=y or
# CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE=y.

# Locate the compact25519 source tree: the west project (../modules/lib/
# compact25519) or the libedhoc externals/ submodule. Override with
# -DCOMPACT25519_ROOT=.
if(NOT DEFINED COMPACT25519_ROOT)
    foreach(_c25519_cand
            ${ZEPHYR_CURRENT_MODULE_DIR}/../modules/lib/compact25519
            ${ZEPHYR_CURRENT_MODULE_DIR}/externals/compact25519)
        if(EXISTS ${_c25519_cand}/src/compact_ed25519.c)
            set(COMPACT25519_ROOT ${_c25519_cand})
            break()
        endif()
    endforeach()
endif()

if(NOT COMPACT25519_ROOT OR NOT EXISTS ${COMPACT25519_ROOT}/src/compact_ed25519.c)
    message(FATAL_ERROR
            "libedhoc suites 0/4: compact25519 sources not found (looked in "
            "../modules/lib/compact25519 and externals/compact25519). Pass "
            "-DCOMPACT25519_ROOT=<path>.")
endif()

zephyr_library_named(compact25519)
zephyr_library_sources(
    ${COMPACT25519_ROOT}/src/compact_ed25519.c
    ${COMPACT25519_ROOT}/src/compact_wipe.c
    ${COMPACT25519_ROOT}/src/compact_x25519.c
    ${COMPACT25519_ROOT}/src/c25519/c25519.c
    ${COMPACT25519_ROOT}/src/c25519/ed25519.c
    ${COMPACT25519_ROOT}/src/c25519/edsign.c
    ${COMPACT25519_ROOT}/src/c25519/f25519.c
    ${COMPACT25519_ROOT}/src/c25519/fprime.c
    ${COMPACT25519_ROOT}/src/c25519/sha512.c)

# Vendored third-party sources: do not fail the build on their warnings.
zephyr_library_compile_options(-w)

# Global include paths so the suite 0 / 4 reference sources (compiled by the
# application) resolve "compact_ed25519.h" and the c25519 primitives.
zephyr_include_directories(
    ${COMPACT25519_ROOT}/src
    ${COMPACT25519_ROOT}/src/c25519)
