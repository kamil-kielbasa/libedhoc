# =============================================================================
# tests/ — libedhoc Linux test tree.
#
#   * tests/linux/  : migrated, standalone per-suite/per-scenario Unity binaries
#                     (cipher_suites, integration, rfc9529), each sized by the
#                     active preset — this is what solves the single-binary
#                     buffer-inflation problem.
#   * libedhoc_module_tests : the TRANSITIONAL monolith holding the not-yet-
#                     migrated unit tier. It is cross-suite (test_api binds
#                     suites 0/2/24 together) and only builds when all three are
#                     enabled (the `legacy` preset and the default all-suites
#                     build); it is removed when the unit tier is migrated to a
#                     suite-agnostic form under tests/linux/unit.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

add_subdirectory(linux)

# --- Transitional unit monolith ----------------------------------------------
# test_api exercises suites 0, 2 and 24 in one binary, so this only builds when
# all three are enabled (the `legacy` preset and the default all-suites build).
if (CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE AND
    CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE AND
    CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE)

project(libedhoc_module_tests)

# --- Test sources (tier lists) -----------------------------------------------

set(TEST_MAIN
    test_main.c)

set(TEST_COMMON_SOURCES
    common/src/test_ead.c
    common/src/test_credentials.c)

set(TEST_UNIT_SOURCES
    unit/api/test_api.c
    unit/api/test_api_negative.c
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
        unit/mem/test_mem_custom.c)
endif()

set(TEST_HELPER_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES})

set_source_files_properties(${TEST_HELPER_SOURCES} PROPERTIES
                            COMPILE_FLAGS "-Wno-format -Wno-format-pedantic -Wno-sign-conversion -Wno-conversion -Wno-switch-enum")

# --- Executable --------------------------------------------------------------

add_executable(${PROJECT_NAME}
               ${TEST_MAIN}
               ${TEST_COMMON_SOURCES}
               ${TEST_UNIT_SOURCES}
               ${TEST_MEM_CUSTOM_SOURCES}
               ${TEST_HELPER_SOURCES})

# --- Compile definitions -----------------------------------------------------

if (LIBEDHOC_ENABLE_TESTS_TRACES)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TEST_TRACES)
endif()

# --- Include directories -----------------------------------------------------

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/common/include
                           ${LIBEDHOC_INTERNAL_INCLUDE_DIR})

# --- Link dependencies -------------------------------------------------------

target_link_libraries(${PROJECT_NAME} PRIVATE
                      libedhoc::edhoc
                      libedhoc::cipher_suites
                      libedhoc::backend_memory
                      unity)

if (CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
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

add_test(NAME ${PROJECT_NAME} COMMAND libedhoc_module_tests)

endif()
