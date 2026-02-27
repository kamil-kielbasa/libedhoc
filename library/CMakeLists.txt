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

# Strict warning flags shared by both GCC and Clang (standalone builds only).
# Zephyr has its own flags and uses -std=c99 which conflicts with -pedantic.
if (NOT TARGET zephyr_interface)

    set(LIBEDHOC_COMMON_WARNINGS
        -Werror
        -Wall
        -Wextra
        -pedantic

        # Type safety
        -Wconversion
        -Wsign-conversion
        -Wcast-align
        -Wdouble-promotion

        # Format strings
        -Wformat=2

        # Control flow
        -Wunreachable-code

        # Declarations
        -Wmissing-declarations
        -Wmissing-prototypes
        -Wstrict-prototypes
        -Wold-style-definition
        -Wnested-externs

        # General
        -Wshadow
        -Wundef
        -Wwrite-strings
        -Wpointer-arith
        -Wuninitialized
        -Wmissing-include-dirs
        -Wnull-dereference)

    if (LIBEDHOC_BUILD_COMPILER_GCC)
        target_compile_options(${PROJECT_NAME} PRIVATE
                               ${LIBEDHOC_COMMON_WARNINGS}

                               # GCC-specific
                               -Wformat-overflow=2
                               -Wformat-truncation=2
                               -Wswitch-enum
                               -Wjump-misses-init
                               -Wduplicated-cond
                               -Wduplicated-branches
                               -Wlogical-op
                               -Winit-self)
    endif()

    if (LIBEDHOC_BUILD_COMPILER_CLANG)
        target_compile_options(${PROJECT_NAME} PRIVATE
                               ${LIBEDHOC_COMMON_WARNINGS}

                               # Clang-specific
                               -Wno-vla
                               -Wno-declaration-after-statement
                               -Wno-covered-switch-default
                               -Wno-padded
                               -Wno-switch-default)

        # -Wunsafe-buffer-usage exists in Clang 16+; suppress if available.
        # Test the positive form because Clang silently ignores unknown -Wno-*.
        include(CheckCCompilerFlag)
        check_c_compiler_flag(-Wunsafe-buffer-usage HAS_WUNSAFE_BUFFER_USAGE)
        if (HAS_WUNSAFE_BUFFER_USAGE)
            target_compile_options(${PROJECT_NAME} PRIVATE -Wno-unsafe-buffer-usage)
        endif()
    endif()

    # Stack hardening (disabled under sanitizers — conflicts with ASan)
    if (NOT LIBEDHOC_ENABLE_SANITIZERS)
        target_compile_options(${PROJECT_NAME} PRIVATE -fstack-protector-strong)
    endif()

endif()

if (LIBEDHOC_ENABLE_MODULE_TESTS)
    target_compile_definitions(${PROJECT_NAME} PRIVATE LIBEDHOC_TEST_HOOKS)
endif()

if (LIBEDHOC_ENABLE_COVERAGE)
    target_compile_options(${PROJECT_NAME} PRIVATE --coverage)
    target_link_options(${PROJECT_NAME} PUBLIC --coverage)
endif()

if (LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(${PROJECT_NAME} PRIVATE
                           -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${PROJECT_NAME} PUBLIC
                        -fsanitize=address,undefined)
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
