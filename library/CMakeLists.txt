# =============================================================================
# libedhoc::edhoc — the core EDHOC implementation (standalone build).
# The Zephyr build creates its own library from the same source list
# (cmake/sources.cmake), so this file is now Zephyr-free.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

add_library(libedhoc STATIC ${LIBEDHOC_CORE_SOURCES})
add_library(libedhoc::edhoc ALIAS libedhoc)

# --- Dependency surface ------------------------------------------------------
# PUBLIC : the public headers are the API contract.
# PRIVATE: backends are an implementation detail. Nothing in the public headers
#          refers to them, so consumers must not inherit their header paths.
#          For a static library, PRIVATE dependencies still propagate as
#          link-only requirements, so downstream linking keeps working.
target_link_libraries(libedhoc
    PUBLIC  libedhoc::api
    PRIVATE libedhoc::backend_cbor
            libedhoc::backend_memory
            libedhoc::backend_log)

# Crypto libraries are used by the crypto callbacks in tests, helpers and
# applications, not by the crypto-agnostic core. Kept BUILD_INTERFACE-only so
# they are absent from the install export.
target_link_libraries(libedhoc PUBLIC
    $<BUILD_INTERFACE:mbedtls>
    $<BUILD_INTERFACE:compact25519>
    $<BUILD_INTERFACE:zcbor>)

# --- Strict warnings (PRIVATE: never inflicted on consumers) -----------------
libedhoc_target_warnings(libedhoc STRICT)

# Stack hardening (disabled under sanitizers — conflicts with ASan)
if(NOT LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(libedhoc PRIVATE -fstack-protector-strong)
endif()

# --- Optional instrumentation ------------------------------------------------
# LIBEDHOC_MODULE_TESTS makes internal STATIC functions externally visible so
# module tests can link against them.  Enabled only when tests are built.
if(LIBEDHOC_ENABLE_TESTS)
    target_compile_definitions(libedhoc PRIVATE LIBEDHOC_MODULE_TESTS)
endif()

if(LIBEDHOC_ENABLE_COVERAGE)
    target_compile_options(libedhoc PRIVATE --coverage)
    target_link_options(libedhoc PUBLIC --coverage)
endif()

if(LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(libedhoc PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(libedhoc PUBLIC -fsanitize=address,undefined)
endif()

# The exported name matches the in-tree alias suffix, so find_package() and
# add_subdirectory() consumers both write libedhoc::edhoc.
set_target_properties(libedhoc PROPERTIES EXPORT_NAME edhoc)
