# =============================================================================
# libedhoc_fuzz — LibFuzzer targets for message parsing.
# =============================================================================

project(libedhoc_fuzz)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/sources.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/warnings.cmake)

# --- Fuzz sources ------------------------------------------------------------

set(FUZZ_COMMON_SOURCES
    ${LIBEDHOC_FUZZ_CIPHER_SUITE_SOURCES}
    ${LIBEDHOC_TEST_COMMON_SOURCES})

set(FUZZ_TARGETS
    fuzz_message_1_process
    fuzz_message_2_process
    fuzz_message_3_process
    fuzz_message_4_process
    fuzz_message_error_process)

# --- Fuzz executables --------------------------------------------------------

foreach(target ${FUZZ_TARGETS})
    add_executable(${target}
                   ${target}.c
                   ${FUZZ_COMMON_SOURCES})

    target_include_directories(${target} PRIVATE
                               ${LIBEDHOC_TESTS_DIR}/common/include
                               ${LIBEDHOC_INTERNAL_INCLUDE_DIR})

    target_link_libraries(${target} PRIVATE
                          libedhoc::edhoc
                          libedhoc::cipher_suites
                          libedhoc::backend_memory
                          unity)

    # Same shared warning policy as the library and module tests (TEST profile:
    # tolerates Unity macros and CBOR test-vector casts).
    libedhoc_target_warnings(${target} TEST)

    # Fuzz-specific: LLVMFuzzerTestOneInput is the libFuzzer entry point, called
    # by the fuzzer runtime — it has no prototype in any header by design.
    target_compile_options(${target} PRIVATE -Wno-missing-prototypes)

    target_compile_options(${target} PRIVATE
                           -fsanitize=fuzzer,address,undefined
                           -fno-omit-frame-pointer -g)

    target_link_options(${target} PRIVATE
                        -fsanitize=fuzzer,address,undefined)
endforeach()
