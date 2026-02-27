cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(libedhoc_benchmark)

# Make user-mbedtls.h findable by mbedtls library sources.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})

target_sources(app PRIVATE
    src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../helpers/src/edhoc_cipher_suite_2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../helpers/src/edhoc_helpers.c)

target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../helpers/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../backends/cbor/include
    ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(app PRIVATE _POSIX_C_SOURCE=200809L)

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
