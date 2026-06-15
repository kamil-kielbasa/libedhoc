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
    target_compile_definitions(zcbor PRIVATE CONFIG_ZCBOR)
    target_compile_definitions(zcbor PRIVATE ZCBOR_CANONICAL)
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
