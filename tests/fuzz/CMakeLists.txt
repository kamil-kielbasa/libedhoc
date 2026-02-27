project(libedhoc_fuzz)

set(FUZZ_COMMON_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../../helpers/src/edhoc_cipher_suite_0.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../helpers/src/edhoc_cipher_suite_2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../helpers/src/edhoc_helpers.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/test_ead.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/test_cipher_suites.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/test_credentials.c)

set(FUZZ_TARGETS
    fuzz_message_1_process
    fuzz_message_2_process
    fuzz_message_3_process
    fuzz_message_4_process
    fuzz_message_error_process)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target}
                   ${target}.c
                   ${FUZZ_COMMON_SOURCES})

    target_include_directories(${target} PRIVATE
                               ${CMAKE_CURRENT_SOURCE_DIR}/../../helpers/include
                               ${CMAKE_CURRENT_SOURCE_DIR}/../../backends/cbor/include
                               ${CMAKE_CURRENT_SOURCE_DIR}/../common/include)

    target_link_libraries(${target} PRIVATE
                          libedhoc
                          libedhoc_api
                          unity)

    target_compile_options(${target} PRIVATE
                           -fsanitize=fuzzer,address,undefined
                           -fno-omit-frame-pointer -g)

    target_link_options(${target} PRIVATE
                        -fsanitize=fuzzer,address,undefined)
endforeach()
