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
# pulled into the partial link remain unresolved at the NSI stage, so the
# mbedtls archives must be provided to the NSI runner link.
#
# Zephyr >= 4.x splits mbedTLS into TF-PSA-Crypto: the crypto core builds as the
# tfpsacrypto target alongside the mbedtls / mbedx509 archives (older Zephyr
# shipped a single mbedTLSCrypto / mbedTLSBase / mbedTLSX509 set).
#
# RUNNER_LINK_LIBRARIES is emitted verbatim into nsi_config via
# $<JOIN:$<TARGET_PROPERTY:...>> and then consumed by make (natsim_config.cmake),
# so generator expressions stored here (e.g. $<TARGET_FILE:>) are NOT
# re-evaluated: they would leak literally into the Makefile and break its parse.
# Resolve each archive path at configure time from the target's own binary
# directory instead, so the mbedtls on-disk layout is never hard-coded here.
if(TARGET native_simulator)
  set(_edhoc_nsi_mbedtls_libs "")
  foreach(_lib tfpsacrypto mbedtls mbedx509              # Zephyr >= 4.x
               mbedTLSCrypto mbedTLSBase mbedTLSX509)    # legacy Zephyr <= 3.x
    if(TARGET ${_lib})
      get_target_property(_edhoc_lib_dir ${_lib} BINARY_DIR)
      list(APPEND _edhoc_nsi_mbedtls_libs ${_edhoc_lib_dir}/lib${_lib}.a)
    endif()
  endforeach()
  if(_edhoc_nsi_mbedtls_libs)
    set_property(TARGET native_simulator APPEND PROPERTY
                 RUNNER_LINK_LIBRARIES ${_edhoc_nsi_mbedtls_libs})
  endif()
endif()
