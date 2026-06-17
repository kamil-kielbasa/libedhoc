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

# --- liboqs (post-quantum primitives for experimental cipher suite 1) --------

if (LIBEDHOC_ENABLE_EXPERIMENTAL_PQC AND NOT TARGET oqs)
    set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    set(OQS_MINIMAL_BUILD "KEM_ml_kem_512;SIG_ml_dsa_44" CACHE STRING "" FORCE)
    set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
    add_subdirectory(liboqs)
endif()
