# =============================================================================
# Zephyr module entry point.
#
# Builds the library from the shared source lists in cmake/sources.cmake and
# keeps all Zephyr-specific wiring in this directory.
# =============================================================================

if(CONFIG_LIBEDHOC_ENABLE)
    include(${CMAKE_CURRENT_LIST_DIR}/../cmake/sources.cmake)

    # CONFIG_LIBEDHOC_* comes from Kconfig, so there is no generated header here.
    zephyr_library_named(libedhoc)
    zephyr_library_sources(
        ${LIBEDHOC_CORE_SOURCES}
        ${LIBEDHOC_BACKEND_CBOR_SOURCES})

    # Global, so applications compiling the reference suite sources resolve them too.
    zephyr_include_directories(
        ${LIBEDHOC_PUBLIC_INCLUDE_DIR}
        ${LIBEDHOC_INTERNAL_INCLUDE_DIR}
        ${LIBEDHOC_CIPHER_SUITE_INCLUDE_DIRS}
        ${LIBEDHOC_BACKEND_CBOR_INCLUDE_DIR}
        ${LIBEDHOC_BACKEND_MEM_INCLUDE_DIR}
        ${LIBEDHOC_BACKEND_LOG_INCLUDE_DIR})

    # Companion libraries for dependencies that have no upstream Zephyr module.
    if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE OR
       CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE)
        include(${CMAKE_CURRENT_LIST_DIR}/cmake/compact25519.cmake)
    endif()
    if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
        include(${CMAKE_CURRENT_LIST_DIR}/cmake/xkcp.cmake)
    endif()
endif()
