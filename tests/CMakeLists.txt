project(libedhoc_tests)

add_executable(${PROJECT_NAME}
               ${CMAKE_CURRENT_SOURCE_DIR}/src/cipher_suite_negotiation/test_edhoc_cipher_suite_negotiation.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/cipher_suites/cipher_suite_0.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/cipher_suites/cipher_suite_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/cipher_suites/test_cipher_suite_0.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/cipher_suites/test_cipher_suite_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/edhoc_trace_1/authentication_credentials_1.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/edhoc_trace_1/test_edhoc_handshake_1.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/edhoc_trace_1/test_edhoc_handshake_ead_1.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/edhoc_trace_2/authentication_credentials_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/edhoc_trace_2/test_edhoc_handshake_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/error_message/test_edhoc_error_message.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_chain_cs_0/authentication_credentials_x5chain_cs_0.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_chain_cs_0/test_edhoc_handshake_x5chain_cs_0.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_chain_cs_2/authentication_credentials_x5chain_cs_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_chain_cs_2/test_edhoc_handshake_x5chain_cs_2_ead.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_chain_cs_2/test_edhoc_handshake_x5chain_cs_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_hash_cs_2/authentication_credentials_x5t_cs_2.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_hash_cs_2/test_edhoc_handshake_x5t_cs_2_ead.c
               ${CMAKE_CURRENT_SOURCE_DIR}/src/tests.c)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} PUBLIC
                      libedhoc_api
                      libedhoc)
