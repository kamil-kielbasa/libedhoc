project(libedhoc)

if(LIBEDHOC_BUILD_EXTERNAL_DEPS)
    set(CMAKE_C_COMPILER ${LIBEDHOC_COMPILER})
endif()

# For Zephyr builds, the library is already created by zephyr_library_named()
if(NOT TARGET ${PROJECT_NAME})
    add_library(${PROJECT_NAME} STATIC)
endif()

set(LIBEDHOC_SOURCES
    edhoc.c
    edhoc_message_1.c
    edhoc_message_2.c
    edhoc_message_3.c
    edhoc_message_4.c
    edhoc_message_error.c
    edhoc_exporter.c
    edhoc_common.c)

if(TARGET zephyr_interface)
    list(APPEND LIBEDHOC_SOURCES
        ../port/log/zephyr/edhoc_log_backend.c)
endif()

target_sources(${PROJECT_NAME} PRIVATE ${LIBEDHOC_SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                           $<INSTALL_INTERFACE:include>)

if(NOT TARGET zephyr_interface)
    # For Zephyr targets it causes warnings/errors because of the duplicate definitions
    # Set default log level for Linux builds if not already defined
    if(NOT DEFINED CONFIG_LIBEDHOC_LOG_LEVEL)
        set(CONFIG_LIBEDHOC_LOG_LEVEL 3)  # EDHOC_LOG_LEVEL_INF
    endif()
    
    set(LIBEDHOC_DEFINITIONS
        CONFIG_LIBEDHOC_ENABLE=${CONFIG_LIBEDHOC_ENABLE}
        CONFIG_LIBEDHOC_KEY_ID_LEN=${CONFIG_LIBEDHOC_KEY_ID_LEN}
        CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES=${CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES}
        CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=${CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID}
        CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY=${CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY}
        CONFIG_LIBEDHOC_MAX_LEN_OF_MAC=${CONFIG_LIBEDHOC_MAX_LEN_OF_MAC}
        CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS=${CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS}
        CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=${CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID}
        CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG=${CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG}
        CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=${CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN}
        CONFIG_LIBEDHOC_LOG_LEVEL=${CONFIG_LIBEDHOC_LOG_LEVEL})

    target_compile_definitions(${PROJECT_NAME} PUBLIC ${LIBEDHOC_DEFINITIONS})
endif()

# Only apply strict compile options for standalone builds, not Zephyr builds
# (Zephyr has its own flags and uses -std=c99 which conflicts with -pedantic)
if (LIBEDHOC_BUILD_COMPILER_GCC AND NOT TARGET zephyr_interface)
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
                           -Wunreachable-code)
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
                           -Wno-padded
                           -Wno-unsafe-buffer-usage
                           -Wno-switch-default)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC
                      libedhoc_api
                      backend_cbor)

if (NOT TARGET zephyr_interface)
    target_link_libraries(${PROJECT_NAME} PUBLIC
                          $<BUILD_INTERFACE:mbedtls>
                          $<BUILD_INTERFACE:compact25519>
                          $<BUILD_INTERFACE:zcbor>)
endif()
