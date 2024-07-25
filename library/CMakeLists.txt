project(libedhoc)

set(CMAKE_C_COMPILER ${LIBEDHOC_COMPILER})

add_library(${PROJECT_NAME} STATIC)

target_sources(${PROJECT_NAME} PRIVATE
               edhoc.c
               edhoc_message_1.c
               edhoc_message_2.c
               edhoc_message_3.c
               edhoc_message_4.c
               edhoc_message_error.c
               edhoc_exporter.c
               edhoc_common.c)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(${PROJECT_NAME} PUBLIC
                           -DEDHOC_KID_LEN=4
                           -DEDHOC_MAX_CSUITES_LEN=4
                           -DEDHOC_MAX_CID_LEN=1
                           -DEDHOC_MAX_ECC_KEY_LEN=32
                           -DEDHOC_MAX_MAC_LEN=32
                           -DEDHOC_MAX_NR_OF_EAD_TOKENS=5
                           -DEDHOC_CRED_KEY_ID_LEN=1
                           -DEDHOC_CRED_X509_HASH_ALG_LEN=1
                           -DEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=2)

if (LIBEDHOC_BUILD_COMPILER_GCC)
    target_compile_options(${PROJECT_NAME} PRIVATE
                           -g3
                           -O0
                           -Werror
                           -Wno-format-security
                           -Wall
                           -Wextra
                           -pedantic
                           -Wcast-align
                           -Winit-self
                           -Wlogical-op
                           -Wmissing-include-dirs
                           -Wshadow
                           -Wundef
                           -Wwrite-strings
                           -Wpointer-arith
                           -Wmissing-declarations
                           -Wuninitialized
                           -Wold-style-definition
                           -Wstrict-prototypes
                           -Wmissing-prototypes
                           -Wnested-externs
                           -Wunreachable-code
                          )
endif()
    
if (LIBEDHOC_BUILD_COMPILER_CLANG)
    target_compile_options(${PROJECT_NAME} PRIVATE
                           -g3
                           -O0
                           -Werror
                           -Weverything
                           -Wno-vla
                           -Wno-declaration-after-statement
                           -Wno-covered-switch-default
                           -Wno-padded)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC
                      libedhoc_api
                      mbedtls
                      compact25519
                      zcbor
                      backend_cbor)
