# =============================================================================
# Vendored third-party dependencies for the standalone build.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/externals_sources.cmake)

# --- mbedtls (upstream CMake) ------------------------------------------------

if (NOT TARGET mbedtls)
    add_subdirectory(mbedtls)
endif()

# --- zcbor -------------------------------------------------------------------

if (NOT TARGET zcbor)
    add_library(zcbor STATIC ${LIBEDHOC_ZCBOR_SOURCES})
    target_compile_definitions(zcbor PRIVATE ${LIBEDHOC_ZCBOR_COMPILE_DEFINITIONS})
    target_include_directories(zcbor PUBLIC ${LIBEDHOC_ZCBOR_INCLUDE_DIR})
endif()

# --- compact25519 ------------------------------------------------------------

if (NOT TARGET compact25519)
    add_library(compact25519 STATIC ${LIBEDHOC_COMPACT25519_SOURCES})
    target_include_directories(compact25519 PUBLIC ${LIBEDHOC_COMPACT25519_INCLUDE_DIRS})
endif()

# --- unity -------------------------------------------------------------------

if (NOT TARGET unity)
    add_library(unity STATIC ${LIBEDHOC_UNITY_SOURCES})
    target_compile_definitions(unity PUBLIC UNITY_OUTPUT_COLOR)
    target_include_directories(unity PUBLIC ${LIBEDHOC_UNITY_INCLUDE_DIRS})
endif()

# --- liboqs (post-quantum primitives for cipher suite 1) ---------------------

if (CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE AND NOT TARGET oqs)
    set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    set(OQS_MINIMAL_BUILD "KEM_ml_kem_512;SIG_ml_dsa_44" CACHE STRING "" FORCE)
    set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
    add_subdirectory(liboqs)
endif()

# --- XKCP (SP800-185 KMAC256 for the EDHOC_Extract/Expand KDF) ----------------
#
# XKCP ships its own build system that knows the correct file/header set per
# platform, so the most robust integration is to let that build produce
# libXKCP.a and link the result. The reference target (plain-64bit permutation,
# matching liboqs) is generic64; it needs `make`, a C compiler and `xsltproc`.
#
# The resulting archive exposes KMAC256 (SP800-185.h). Its permutation symbols
# are implementation-suffixed (KeccakP1600_plain64_*), so they do not clash with
# the Keccak code liboqs vendors. Should a `multiple definition of Keccak...`
# ever appear, harden the archive so KMAC256 is its only global symbol:
#
#   cd bin/generic64 && mkdir -p _kdf && cd _kdf
#   ar x ../libXKCP.a && ld -r *.o -o combined.o
#   printf 'KMAC256\n' > keep.txt
#   objcopy --keep-global-symbols=keep.txt combined.o kdf.o
#   ar rcs libXKCP_kdf.a kdf.o          # link this instead of libXKCP.a
#
if (CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE AND NOT TARGET xkcp)
    include(ExternalProject)
    set(XKCP_SRC ${CMAKE_CURRENT_SOURCE_DIR}/XKCP)

    ExternalProject_Add(xkcp_build
        SOURCE_DIR        ${XKCP_SRC}
        CONFIGURE_COMMAND ""
        BUILD_IN_SOURCE   1
        BUILD_COMMAND     make generic64/libXKCP.a
        INSTALL_COMMAND   ""
        BUILD_BYPRODUCTS  ${XKCP_SRC}/bin/generic64/libXKCP.a)

    add_library(xkcp STATIC IMPORTED GLOBAL)
    add_dependencies(xkcp xkcp_build)
    set_target_properties(xkcp PROPERTIES
        IMPORTED_LOCATION ${XKCP_SRC}/bin/generic64/libXKCP.a)

    # Public XKCP headers (SP800-185.h among them) are collected here by the
    # build. Exposed as a cache variable so tests/samples can add it to their
    # include path without re-deriving the location.
    set(XKCP_INCLUDE_DIR ${XKCP_SRC}/bin/generic64/libXKCP.a.headers
        CACHE INTERNAL "XKCP public headers")
endif()
