# =============================================================================
# libedhoc_benchmark — Zephyr native_sim benchmark application.
# =============================================================================

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(libedhoc_benchmark)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/sources.cmake)

# --- Sample-private includes -------------------------------------------------

# Make user-mbedtls.h findable by mbedtls library sources.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# --- App sources -------------------------------------------------------------

# Helper sources are compiled into the app; the libedhoc, helper and backend
# include paths come from the Zephyr module, so only the sample-private
# test-vector headers need a manual include.
target_sources(app PRIVATE
    src/main.c
    ${LIBEDHOC_BENCHMARK_CIPHER_SUITE_SOURCES})

target_include_directories(app PRIVATE
    ${LIBEDHOC_TESTS_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR})

# --- Compile definitions -----------------------------------------------------

target_compile_definitions(app PRIVATE _POSIX_C_SOURCE=200809L)

# --- native_sim mbedtls runner link ------------------------------------------

# native_sim two-stage linking: zephyr.elf (partial link -r) → objcopy →
# re-link into zephyr.exe.  Symbols from mbedtls archives that were NOT
# pulled into the partial link remain unresolved at the NSI stage.
# Provide all mbedtls libraries to the NSI runner link.
if(TARGET native_simulator)
  set(MBEDTLS_LIB_DIR ${CMAKE_BINARY_DIR}/modules/mbedtls)
  set_property(TARGET native_simulator APPEND PROPERTY
               RUNNER_LINK_LIBRARIES
               ${MBEDTLS_LIB_DIR}/libmbedTLSCrypto.a
               ${MBEDTLS_LIB_DIR}/libmbedTLSBase.a
               ${MBEDTLS_LIB_DIR}/libmbedTLSX509.a)
endif()
