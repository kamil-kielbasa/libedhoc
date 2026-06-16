# =============================================================================
# Source and include lists for vendored third-party dependencies.
# Consumed by externals/CMakeLists.txt and externals/zcbor-cmake/CMakeLists.txt.
# All paths are absolute (CMAKE_CURRENT_LIST_DIR is this file's directory).
# =============================================================================

set(LIBEDHOC_EXTERNALS_DIR ${CMAKE_CURRENT_LIST_DIR}/../externals)

set(LIBEDHOC_ZCBOR_SOURCES
    ${LIBEDHOC_EXTERNALS_DIR}/zcbor/src/zcbor_common.c
    ${LIBEDHOC_EXTERNALS_DIR}/zcbor/src/zcbor_decode.c
    ${LIBEDHOC_EXTERNALS_DIR}/zcbor/src/zcbor_encode.c)

set(LIBEDHOC_ZCBOR_INCLUDE_DIR ${LIBEDHOC_EXTERNALS_DIR}/zcbor/include)

set(LIBEDHOC_ZCBOR_COMPILE_DEFINITIONS ZCBOR_CANONICAL)

set(LIBEDHOC_COMPACT25519_SOURCES
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/compact_ed25519.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/compact_wipe.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/compact_x25519.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/c25519/c25519.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/c25519/ed25519.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/c25519/edsign.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/c25519/f25519.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/c25519/fprime.c
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/c25519/sha512.c)

set(LIBEDHOC_COMPACT25519_INCLUDE_DIRS
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src
    ${LIBEDHOC_EXTERNALS_DIR}/compact25519/src/c25519)

set(LIBEDHOC_UNITY_SOURCES
    ${LIBEDHOC_EXTERNALS_DIR}/Unity/src/unity.c
    ${LIBEDHOC_EXTERNALS_DIR}/Unity/extras/fixture/src/unity_fixture.c
    ${LIBEDHOC_EXTERNALS_DIR}/Unity/extras/memory/src/unity_memory.c)

set(LIBEDHOC_UNITY_INCLUDE_DIRS
    ${LIBEDHOC_EXTERNALS_DIR}/Unity/src
    ${LIBEDHOC_EXTERNALS_DIR}/Unity/extras/fixture/src
    ${LIBEDHOC_EXTERNALS_DIR}/Unity/extras/memory/src)
