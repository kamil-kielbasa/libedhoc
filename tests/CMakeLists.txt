project(libedhoc_module_tests)

add_executable(${PROJECT_NAME}
               src/module_test_main.c
               src/module_test_cipher_suite_0.c
               src/module_test_cipher_suite_2.c
               src/module_test_rfc9529_chapter_2.c
               src/module_test_rfc9529_chapter_3.c
               src/module_test_rfc9528_suites_negotiation.c
               src/module_test_error_message.c
               src/module_test_x5chain_sign_keys_suite_0.c
               src/module_test_x5chain_sign_keys_suite_2.c
               src/module_test_x5chain_static_dh_keys_suite_2.c
               src/module_test_x5t_sign_keys_suite_2.c
               src/module_test_api.c
               src/module_test_edhoc_helpers.c
               ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/src/edhoc_cipher_suite_0.c
               ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/src/edhoc_cipher_suite_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/src/edhoc_helpers.c)

if (LIBEDHOC_ENABLE_MODULE_TESTS_TRACES)
        target_compile_definitions(${PROJECT_NAME} PUBLIC
                                   TEST_TRACES)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/../helpers/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/../backends/cbor/include)

target_link_libraries(${PROJECT_NAME} PUBLIC
                      libedhoc
                      libedhoc_api
                      unity)

add_test(${PROJECT_NAME} libedhoc_module_tests)
