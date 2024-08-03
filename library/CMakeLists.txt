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
                           CONFIG_LIBEDHOC_ENABLE=1
                           CONFIG_LIBEDHOC_KEY_ID_LEN=4
                           CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES=3
                           CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=1
                           CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY=32
                           CONFIG_LIBEDHOC_MAX_LEN_OF_MAC=32
                           CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS=3
                           CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=1
                           CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG=1
                           CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=2)

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
