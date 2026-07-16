# =============================================================================
# libedhoc_module_tests — standalone module test executable.
# =============================================================================

project(libedhoc_module_tests)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

# --- Test sources (tier lists) -----------------------------------------------

set(TEST_MAIN
    test_main.c)

set(TEST_COMMON_SOURCES
    common/src/test_ead.c
    common/src/test_credentials.c)

set(TEST_UNIT_SOURCES
    unit/api/test_api.c
    unit/api/test_api_negative.c
    unit/cipher_suites/test_cipher_suite_0.c
    unit/cipher_suites/test_cipher_suite_2.c
    unit/cipher_suites/test_cipher_suite_4.c
    unit/cipher_suites/test_cipher_suite_24.c
    unit/error/test_error_message.c
    unit/exporters/test_exporters.c
    unit/coap/test_coap.c
    unit/coverage/coverage_common.c
    unit/coverage/test_coverage_msg1.c
    unit/coverage/test_coverage_msg2.c
    unit/coverage/test_coverage_msg3.c
    unit/coverage/test_coverage_msg4.c
    unit/coverage/test_coverage_exporters.c
    unit/coverage/test_coverage_error.c
    unit/coverage/test_coverage_cbor.c
    unit/coverage/test_coverage_handshake.c
    unit/coverage/test_coverage_sweep_validate.c
    unit/internals/internals_common.c
    unit/internals/test_internals_common.c
    unit/internals/test_internals_mac.c
    unit/internals/test_internals_message2.c
    unit/internals/test_internals_message3.c
    unit/internals/test_internals_message4.c
    unit/internals/test_internals_error.c
    unit/internals/test_internals_message1.c
    unit/internals/test_internals_coap.c
    unit/internals/test_internals_api.c
    unit/message/test_message_paths.c)

if (LIBEDHOC_ENABLE_EXPERIMENTAL_PQC)
    list(APPEND TEST_UNIT_SOURCES
         unit/cipher_suites/test_cipher_suite_exp_pqc_1.c)
endif()

set(TEST_INTEGRATION_SOURCES
    integration/test_handshake_x5chain_sig_suite0.c
    integration/test_handshake_x5chain_sig_suite2.c
    integration/test_handshake_x5chain_sig_suite24.c
    integration/test_handshake_x5chain_dh_suite2.c
    integration/test_handshake_x5t_sig_suite2.c
    integration/test_handshake_auth_methods.c
    integration/test_handshake_handle_balance.c
    integration/test_rfc9528_negotiation.c
    integration/test_rfc9529_chapter2.c
    integration/test_rfc9529_chapter3.c)

# --- Custom memory backend sources -------------------------------------------

# Custom memory backend tests are only meaningful when the library is built with
# the custom backend (-DCONFIG_LIBEDHOC_MEM_BACKEND=2). They provide the
# link-time edhoc_mem_alloc()/edhoc_mem_free() hooks and exercise the
# out-of-memory cleanup paths.
set(TEST_MEM_CUSTOM_SOURCES "")
if (DEFINED CONFIG_LIBEDHOC_MEM_BACKEND AND CONFIG_LIBEDHOC_MEM_BACKEND EQUAL 2)
    set(TEST_MEM_CUSTOM_SOURCES
        common/src/test_mem_custom.c
        common/src/test_mem_custom_handshake.c
        unit/mem/test_mem_custom.c
        integration/test_mem_custom.c)
endif()

set(TEST_HELPER_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES})

set_source_files_properties(${TEST_HELPER_SOURCES} PROPERTIES
                            COMPILE_FLAGS "-Wno-format -Wno-format-pedantic -Wno-sign-conversion -Wno-conversion -Wno-switch-enum")

# --- Executable --------------------------------------------------------------

add_executable(${PROJECT_NAME}
               ${TEST_MAIN}
               ${TEST_COMMON_SOURCES}
               ${TEST_UNIT_SOURCES}
               ${TEST_INTEGRATION_SOURCES}
               ${TEST_MEM_CUSTOM_SOURCES}
               ${TEST_HELPER_SOURCES})

# --- Compile definitions -----------------------------------------------------

if (LIBEDHOC_ENABLE_TESTS_TRACES)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TEST_TRACES)
endif()

if (LIBEDHOC_ENABLE_EXPERIMENTAL_PQC)
    target_compile_definitions(${PROJECT_NAME} PRIVATE LIBEDHOC_ENABLE_EXPERIMENTAL_PQC=1)
endif()

# --- Include directories -----------------------------------------------------

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/common/include
                           ${LIBEDHOC_INTERNAL_INCLUDE_DIR})

# --- Link dependencies -------------------------------------------------------

target_link_libraries(${PROJECT_NAME} PRIVATE
                      libedhoc::edhoc
                      libedhoc::cipher_suites
                      libedhoc::backend_memory
                      unity)

if (LIBEDHOC_ENABLE_EXPERIMENTAL_PQC)
    target_link_libraries(${PROJECT_NAME} PRIVATE oqs)
    target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_BINARY_DIR}/externals/liboqs/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../externals/liboqs/src)

    # XKCP provides SP800-185 KMAC256 for the EDHOC_Extract/Expand KDF.
    target_link_libraries(${PROJECT_NAME} PRIVATE xkcp)
    target_include_directories(${PROJECT_NAME} PRIVATE ${XKCP_INCLUDE_DIR})
    # libXKCP.a and its generated SP800-185.h are produced by the xkcp_build
    # ExternalProject; make the test target wait for it so the helper source can
    # find the header at compile time (not just at link time).
    add_dependencies(${PROJECT_NAME} xkcp_build)
endif()

# --- Warning flags -----------------------------------------------------------
libedhoc_target_warnings(${PROJECT_NAME} TEST)

# --- Instrumentation (coverage, sanitizers) ----------------------------------

if (LIBEDHOC_ENABLE_COVERAGE)
    target_compile_options(${PROJECT_NAME} PRIVATE --coverage)
    target_link_options(${PROJECT_NAME} PRIVATE --coverage)
endif()

if (LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(${PROJECT_NAME} PRIVATE
                           -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${PROJECT_NAME} PRIVATE
                        -fsanitize=address,undefined)
endif()

add_test(${PROJECT_NAME} libedhoc_module_tests)
