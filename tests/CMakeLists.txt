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
    unit/cipher_suites/test_cipher_suite_24.c
    unit/error/test_error_message.c
    unit/exporters/test_exporters.c
    unit/helpers/test_helpers.c
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
    unit/internals/test_internals_helpers.c
    unit/internals/test_internals_api.c
    unit/message/test_message_paths.c)

set(TEST_INTEGRATION_SOURCES
    integration/test_handshake_x5chain_sig_suite0.c
    integration/test_handshake_x5chain_sig_suite2.c
    integration/test_handshake_x5chain_sig_suite24.c
    integration/test_handshake_x5chain_dh_suite2.c
    integration/test_handshake_x5t_sig_suite2.c
    integration/test_handshake_auth_methods.c
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

set(TEST_HELPER_SOURCES ${LIBEDHOC_HELPERS_SOURCES})

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

if (LIBEDHOC_ENABLE_MODULE_TESTS_TRACES)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TEST_TRACES)
endif()

# --- Include directories -----------------------------------------------------

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/common/include)

# --- Link dependencies -------------------------------------------------------

target_link_libraries(${PROJECT_NAME} PRIVATE
                      libedhoc::edhoc
                      libedhoc::helpers
                      libedhoc::backend_memory
                      unity)

# --- Warning flags -----------------------------------------------------------

set(TEST_COMMON_WARNINGS
    -Werror
    -Wall
    -Wextra
    -pedantic

    # Type safety
    -Wconversion
    -Wcast-align
    -Wdouble-promotion

    # Format strings
    -Wformat=2

    # Control flow
    -Wunreachable-code

    # Declarations
    -Wmissing-prototypes
    -Wstrict-prototypes
    -Wold-style-definition

    # General
    -Wshadow
    -Wundef
    -Wwrite-strings
    -Wpointer-arith
    -Wuninitialized
    -Wmissing-include-dirs
    -Wnull-dereference

    # Suppressed for test code:
    # - nested-externs: Unity macros use nested extern declarations
    # - missing-declarations: test functions declared via Unity macros
    # - sign-conversion: test vectors store negative CBOR ints in uint8_t
    -Wno-missing-declarations
    -Wno-sign-conversion)

# Compiler family is detected from CMAKE_C_COMPILER_ID, the same mechanism used
# by the core library.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE
                           ${TEST_COMMON_WARNINGS}

                           # GCC-specific
                           -Wformat-overflow=2
                           -Wformat-truncation=2
                           -Wduplicated-cond
                           -Wduplicated-branches
                           -Wlogical-op
                           -Winit-self

                           # Suppressed (GCC-specific):
                           -Wno-nested-externs)
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE
                           ${TEST_COMMON_WARNINGS})
endif()

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
