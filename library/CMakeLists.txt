# =============================================================================
# libedhoc::edhoc — the core EDHOC implementation (standalone build).
#
# The Zephyr build creates its own library from the same source list in
# cmake/sources.cmake, so nothing here is Zephyr-specific.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

add_library(libedhoc STATIC ${LIBEDHOC_CORE_SOURCES})
add_library(libedhoc::edhoc ALIAS libedhoc)

target_include_directories(libedhoc PRIVATE ${LIBEDHOC_INTERNAL_INCLUDE_DIR})

# --- Dependencies ------------------------------------------------------------

# The public headers are the API contract; the backends are an implementation
# detail and must not leak their header paths to consumers.
target_link_libraries(libedhoc
    PUBLIC  libedhoc::api
    PRIVATE libedhoc::backend_cbor
            libedhoc::backend_memory
            libedhoc::backend_log)

# The core itself is crypto-agnostic; these serve the crypto callbacks in tests,
# helpers and applications. BUILD_INTERFACE-only, so absent from the export.
target_link_libraries(libedhoc PUBLIC
    $<BUILD_INTERFACE:${LIBEDHOC_CIPHER_SUITE_CRYPTO_BACKENDS}>
    $<BUILD_INTERFACE:zcbor>)

# --- Warnings and instrumentation --------------------------------------------

libedhoc_target_warnings(libedhoc STRICT)

# Stack hardening conflicts with ASan.
if(NOT LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(libedhoc PRIVATE -fstack-protector-strong)
endif()

# Makes internal static functions visible so module tests can link against them.
if(LIBEDHOC_ENABLE_TESTS)
    target_compile_definitions(libedhoc PRIVATE LIBEDHOC_TESTS)
endif()

if(LIBEDHOC_ENABLE_COVERAGE)
    target_compile_options(libedhoc PRIVATE --coverage)
    target_link_options(libedhoc PUBLIC --coverage)
endif()

if(LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(libedhoc PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(libedhoc PUBLIC -fsanitize=address,undefined)
endif()

set_target_properties(libedhoc PROPERTIES EXPORT_NAME edhoc)

add_subdirectory(cipher_suites)
