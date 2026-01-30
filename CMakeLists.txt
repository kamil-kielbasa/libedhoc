cmake_minimum_required(VERSION 3.16)
project(libedhoc)
enable_language(C)
set_property(GLOBAL PROPERTY C_STANDARD 99)

option(LIBEDHOC_ENABLE_MODULE_TESTS "Enable building module tests" OFF)
option(LIBEDHOC_BUILD_COMPILER_GCC "Enable compiling library with gcc" OFF)
option(LIBEDHOC_BUILD_COMPILER_CLANG "Enable compiling library with clang" OFF)
option(LIBEDHOC_BUILD_EXTERNAL_DEPS "Enable building external dependencies" ON)

if (LIBEDHOC_BUILD_COMPILER_GCC AND LIBEDHOC_BUILD_COMPILER_CLANG)
    message(FATAL_ERROR "One compiler option must be chosen!")
elseif (LIBEDHOC_BUILD_COMPILER_GCC)
    set(LIBEDHOC_COMPILER "gcc")
elseif(LIBEDHOC_BUILD_COMPILER_CLANG)
    set(LIBEDHOC_COMPILER "clang")
else()
    message(WARNING "Compiler option not selected")
endif()

if (LIBEDHOC_BUILD_EXTERNAL_DEPS)
    if (NOT TARGET zephyr_interface)
        add_subdirectory(externals)
    endif()
else()
    set(ZCBOR_IMPORT_TARGETS ON)
    find_package(zcbor REQUIRED CONFIG)
endif()

add_subdirectory(backends)
add_subdirectory(include)
add_subdirectory(library)

if (LIBEDHOC_ENABLE_MODULE_TESTS)
    add_subdirectory(tests)
endif()

if (NOT TARGET zephyr_interface AND NOT LIBEDHOC_BUILD_EXTERNAL_DEPS)
    # Installation
    include(GNUInstallDirs)
    set(CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

    install(TARGETS ${PROJECT_NAME} libedhoc_api backend_cbor
        EXPORT ${PROJECT_NAME}-targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(EXPORT ${PROJECT_NAME}-targets
        DESTINATION ${CONFIG_INSTALL_DIR})

    file(GLOB_RECURSE headers "include/*.h")
    install(FILES ${headers}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    set(PROJECT_CONFIG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake")
    install(FILES ${PROJECT_CONFIG}
        DESTINATION ${CONFIG_INSTALL_DIR})

    install(FILES backends/cbor/include/backend_cbor_connection_identifier_decode.h
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/include)
    install(FILES backends/cbor/include/backend_cbor_connection_identifier_encode.h
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/include)
    install(FILES backends/cbor/include/backend_cbor_connection_identifier_types.h
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/include)
    install(FILES helpers/include/edhoc_cipher_suite_2.h
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/include)
    install(FILES helpers/include/edhoc_helpers.h
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/include)
    install(FILES port/log/linux/edhoc_log_backend.h
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/include)
    install(FILES helpers/src/edhoc_cipher_suite_2.c
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/src)
    install(FILES helpers/src/edhoc_helpers.c
        DESTINATION ${CONFIG_INSTALL_DIR}/helpers/src)

    include(CMakePackageConfigHelpers)
    configure_package_config_file(
        "cmake/project-config.cmake.in"
        "${PROJECT_CONFIG}"
        INSTALL_DESTINATION "${CONFIG_INSTALL_DIR}"
    )
endif()
