add_subdirectory(mbedtls)

set(ZCBOR_NAME zcbor)
set(ZCBOR_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/zcbor/src/zcbor_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/zcbor/src/zcbor_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/zcbor/src/zcbor_encode.c)

add_library(${ZCBOR_NAME} STATIC ${ZCBOR_SOURCES})
target_compile_definitions(${ZCBOR_NAME} PRIVATE CONFIG_ZCBOR)
target_compile_definitions(${ZCBOR_NAME} PRIVATE ZCBOR_CANONICAL)
target_include_directories(${ZCBOR_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/zcbor/include)

set(COMPACT25519_NAME compact25519)
set(COMPACT25519_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/compact_ed25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/compact_wipe.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/compact_x25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/c25519/c25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/c25519/ed25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/c25519/edsign.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/c25519/f25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/c25519/fprime.c
    ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/c25519/sha512.c)

add_library(${COMPACT25519_NAME} STATIC ${COMPACT25519_SOURCES})
target_include_directories(${COMPACT25519_NAME} PUBLIC
                           ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src
                           ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/src/c25519)
