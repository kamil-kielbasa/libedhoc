# =============================================================================
# libedhoc_benchmark — Zephyr / native_sim EDHOC handshake benchmark (ZTEST).
#
# Runs the full handshake once per enabled cipher suite and times each protocol
# phase. Self-contained: the driver and X.509 vectors are local to this tree.
# =============================================================================

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(libedhoc_benchmark)

# LIBEDHOC_CIPHER_SUITE_SOURCES follows the enabled CONFIG_LIBEDHOC_CIPHER_SUITE_*
# set, so the app compiles exactly the suites it benchmarks.
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/sources.cmake)

set(_driver ${CMAKE_CURRENT_SOURCE_DIR}/driver)
set(_vectors ${CMAKE_CURRENT_SOURCE_DIR}/vectors)

# Only the custom backend needs a real allocator (a Zephyr k_heap one here).
set(_mem_hook "")
if(CONFIG_LIBEDHOC_MEM_BACKEND_CUSTOM)
    set(_mem_hook ${_driver}/benchmark_mem_custom.c)
endif()

# --- App sources -------------------------------------------------------------

# Each cipher-suite benchmark is its own translation unit, gated on the same
# CONFIG that pulls the suite into LIBEDHOC_CIPHER_SUITE_SOURCES.
set(_suite_sources "")
if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    list(APPEND _suite_sources src/benchmark_suite_0.c)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    list(APPEND _suite_sources src/benchmark_suite_2.c)
endif()
if(CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE)
    list(APPEND _suite_sources src/benchmark_suite_4.c)
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

# --- native_sim runner link --------------------------------------------------

# native_sim links in two stages. Symbols not pulled into the partial link stay
# unresolved at the runner stage, so the mbedtls archives must be handed to it
# explicitly. Their paths come from each target's own binary dir.
if(TARGET native_simulator)
    set(_nsi_mbedtls_libs "")
    foreach(_lib tfpsacrypto mbedtls mbedx509              # Zephyr >= 4.x
                 mbedTLSCrypto mbedTLSBase mbedTLSX509)    # Zephyr <= 3.x
        if(TARGET ${_lib})
            get_target_property(_lib_dir ${_lib} BINARY_DIR)
            list(APPEND _nsi_mbedtls_libs ${_lib_dir}/lib${_lib}.a)
        endif()
    endforeach()
    if(_nsi_mbedtls_libs)
        set_property(TARGET native_simulator APPEND PROPERTY
                     RUNNER_LINK_LIBRARIES ${_nsi_mbedtls_libs})
    endif()
endif()
