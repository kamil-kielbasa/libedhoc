project(libedhoc_module_tests)

# --- Test sources organized by tier ---

set(TEST_MAIN
    test_main.c)

set(TEST_COMMON_SOURCES
    common/src/test_ead.c
    common/src/test_cipher_suites.c
    common/src/test_credentials.c)

set(TEST_UNIT_SOURCES
    unit/test_api.c
    unit/test_api_negative.c
    unit/test_crypto_suite0.c
    unit/test_crypto_suite2.c
    unit/test_error_message.c
    unit/test_exporters.c
    unit/test_helpers.c
    unit/test_coverage.c
    unit/test_internals.c
    unit/test_message_paths.c)

set(TEST_INTEGRATION_SOURCES
    integration/test_handshake_x5chain_sig_suite0.c
    integration/test_handshake_x5chain_sig_suite2.c
    integration/test_handshake_x5chain_dh_suite2.c
    integration/test_handshake_x5t_sig_suite2.c
    integration/test_handshake_auth_methods.c
    integration/test_rfc9528_negotiation.c
    integration/test_rfc9529_chapter2.c
    integration/test_rfc9529_chapter3.c)

set(TEST_HELPER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/src/edhoc_cipher_suite_0.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/src/edhoc_cipher_suite_2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/src/edhoc_helpers.c)

set_source_files_properties(${TEST_HELPER_SOURCES} PROPERTIES
                            COMPILE_FLAGS "-Wno-format -Wno-format-pedantic -Wno-sign-conversion -Wno-conversion -Wno-switch-enum")

add_executable(${PROJECT_NAME}
               ${TEST_MAIN}
               ${TEST_COMMON_SOURCES}
               ${TEST_UNIT_SOURCES}
               ${TEST_INTEGRATION_SOURCES}
               ${TEST_HELPER_SOURCES})

target_compile_definitions(${PROJECT_NAME} PRIVATE LIBEDHOC_TEST_HOOKS)

if (LIBEDHOC_ENABLE_MODULE_TESTS_TRACES)
        target_compile_definitions(${PROJECT_NAME} PUBLIC
                                   TEST_TRACES)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/common/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/../backends/cbor/include)

target_link_libraries(${PROJECT_NAME} PUBLIC
                      libedhoc
                      libedhoc_api
                      unity)

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

if (LIBEDHOC_BUILD_COMPILER_GCC)
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
                           # - jump-misses-init: test_coverage.c uses goto for cleanup
                           -Wno-nested-externs
                           -Wno-jump-misses-init)
endif()

if (LIBEDHOC_BUILD_COMPILER_CLANG)
    target_compile_options(${PROJECT_NAME} PRIVATE
                           ${TEST_COMMON_WARNINGS})
endif()

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
