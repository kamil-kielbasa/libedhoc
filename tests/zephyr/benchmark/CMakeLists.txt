# =============================================================================
# libedhoc_benchmark — Zephyr / native_sim EDHOC handshake benchmark (ZTEST).
#
# Runs the full handshake under every enabled cipher suite, reusing the Linux
# integration handshake driver's credential / EAD callbacks and X.509 test
# vectors, and times each protocol phase.
# =============================================================================

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(libedhoc_benchmark)

# Shared source/include lists (LIBEDHOC_CIPHER_SUITE_SOURCES follows the enabled
# CONFIG_LIBEDHOC_CIPHER_SUITE_* set, so the app compiles exactly the reference
# suites it benchmarks).
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/sources.cmake)

# The benchmark harness (handshake driver, timed spine, reporting, per-case
# runner and the custom memory backend) plus the X.509 test vectors. This tree
# is self-contained and shares nothing with tests/linux.
set(_driver ${CMAKE_CURRENT_SOURCE_DIR}/driver)
set(_vectors ${CMAKE_CURRENT_SOURCE_DIR}/vectors)

# The custom memory backend needs a real allocator (a Zephyr k_heap one here);
# the stack and heap backends do not.
set(_mem_hook "")
if(CONFIG_LIBEDHOC_MEM_BACKEND_CUSTOM)
    set(_mem_hook ${_driver}/benchmark_mem_custom.c)
endif()

# --- App sources -------------------------------------------------------------

# Each cipher-suite benchmark lives in its own translation unit; gate it on the
# same CONFIG that pulls the suite into LIBEDHOC_CIPHER_SUITE_SOURCES, so an app
# never references a suite it did not build.
set(_suite_sources "")
if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    list(APPEND _suite_sources src/benchmark_suite_0.c)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    list(APPEND _suite_sources src/benchmark_suite_2.c)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE)
    list(APPEND _suite_sources src/benchmark_suite_24.c)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
    list(APPEND _suite_sources src/benchmark_suite_pqc_1.c)
endif()

target_sources(app PRIVATE
    src/main.c
    ${_suite_sources}
    ${_driver}/benchmark_credentials.c
    ${_driver}/benchmark_ead.c
    ${_driver}/benchmark_report.c
    ${_driver}/benchmark_suite.c
    ${LIBEDHOC_CIPHER_SUITE_SOURCES}
    ${_mem_hook})

target_include_directories(app PRIVATE ${_driver} ${_vectors})

# --- Compile definitions -----------------------------------------------------

target_compile_definitions(app PRIVATE _POSIX_C_SOURCE=200809L)

# --- native_sim mbedtls runner link ------------------------------------------

# native_sim two-stage linking: symbols from mbedtls archives not pulled into
# the partial link stay unresolved at the NSI stage, so the archives must be
# handed to the runner link. Paths are resolved at configure time from each
# target's own binary dir (see sample/benchmark for the full rationale).
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
