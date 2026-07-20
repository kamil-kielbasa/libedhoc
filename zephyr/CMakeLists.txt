# =============================================================================
# Zephyr module entry point. Builds the library from the shared source lists
# in cmake/sources.cmake, keeping the Zephyr-specific wiring in this one file.
# =============================================================================

if(CONFIG_LIBEDHOC_ENABLE)
    include(${CMAKE_CURRENT_LIST_DIR}/../cmake/sources.cmake)

    # Core and CBOR backend compiled into the Zephyr module library. The
    # CONFIG_LIBEDHOC_* macros come from Kconfig (autoconf.h), so there is no
    # generated configuration header and no -D definitions here.
    zephyr_library_named(libedhoc)
    zephyr_library_sources(
        ${LIBEDHOC_CORE_SOURCES}
        ${LIBEDHOC_BACKEND_CBOR_SOURCES})

    # Header search paths for the module and for applications that compile the
    # helper sources. zephyr_include_directories() is global, which suits a
    # module shipping public, helper and backend headers.
    zephyr_include_directories(
        ${LIBEDHOC_PUBLIC_INCLUDE_DIR}
        ${LIBEDHOC_INTERNAL_INCLUDE_DIR}
        ${LIBEDHOC_CIPHER_SUITE_INCLUDE_DIRS}
        ${LIBEDHOC_BACKEND_CBOR_INCLUDE_DIR}
        ${LIBEDHOC_BACKEND_MEM_INCLUDE_DIR}
        ${LIBEDHOC_BACKEND_LOG_INCLUDE_DIR})

    # Post-quantum cipher suite 1: build the portable XKCP KMAC256 KDF backend
    # as a companion library (liboqs ships its own Zephyr module). The suite and
    # KDF sources are compiled by the application, like the classic suites.
    if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
        include(${CMAKE_CURRENT_LIST_DIR}/../cmake/xkcp_zephyr.cmake)
    endif()
endif()
