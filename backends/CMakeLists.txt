set(BACKEND_CBOR_NAME backend_cbor)
set(BACKEND_CBOR_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_bstr_type_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_bstr_type_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_connection_identifier_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_connection_identifier_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_ead_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_ead_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_enc_structure_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_enc_structure_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_id_cred_x_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_id_cred_x_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_info_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_info_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_int_type_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_int_type_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_1_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_1_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_2_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_2_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_3_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_3_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_4_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_4_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_error_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_message_error_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_plaintext_2_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_plaintext_2_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_plaintext_3_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_plaintext_3_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_plaintext_4_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_plaintext_4_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_sig_structure_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cbor/src/backend_cbor_sig_structure_encode.c)

if(TARGET zephyr_interface)
    zephyr_library_named(${BACKEND_CBOR_NAME})
    target_sources(${BACKEND_CBOR_NAME} PRIVATE ${BACKEND_CBOR_SOURCES})
else()
    add_library(${BACKEND_CBOR_NAME} STATIC ${BACKEND_CBOR_SOURCES})
    target_link_libraries(${BACKEND_CBOR_NAME} PUBLIC
                        zcbor)
endif()

target_include_directories(${BACKEND_CBOR_NAME} PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cbor/include>)
