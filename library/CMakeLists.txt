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
set(LIBEDHOC_COMMON_WARNINGS
    -Werror -Wall -Wextra -pedantic
    -Wconversion -Wsign-conversion -Wcast-align -Wdouble-promotion
    -Wformat=2 -Wunreachable-code
    -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
    -Wold-style-definition -Wnested-externs
    -Wshadow -Wundef -Wwrite-strings -Wpointer-arith -Wuninitialized
    -Wmissing-include-dirs -Wnull-dereference)

# Compiler family is detected from CMAKE_C_COMPILER_ID.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(libedhoc PRIVATE ${LIBEDHOC_COMMON_WARNINGS}
        -Wformat-overflow=2 -Wformat-truncation=2 -Wswitch-enum
        -Wjump-misses-init -Wduplicated-cond -Wduplicated-branches
        -Wlogical-op -Winit-self)
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(libedhoc PRIVATE ${LIBEDHOC_COMMON_WARNINGS}
        -Wno-vla -Wno-declaration-after-statement -Wno-covered-switch-default
        -Wno-padded -Wno-switch-default)
    include(CheckCCompilerFlag)
    check_c_compiler_flag(-Wunsafe-buffer-usage HAS_WUNSAFE_BUFFER_USAGE)
    if(HAS_WUNSAFE_BUFFER_USAGE)
        target_compile_options(libedhoc PRIVATE -Wno-unsafe-buffer-usage)
    endif()
endif()

# Stack hardening (disabled under sanitizers — conflicts with ASan)
if(NOT LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(libedhoc PRIVATE -fstack-protector-strong)
endif()

# --- Optional instrumentation ------------------------------------------------
# LIBEDHOC_MODULE_TESTS makes internal STATIC functions externally visible so
# module tests can link against them.  Enabled only when module tests are built.
if(LIBEDHOC_ENABLE_MODULE_TESTS)
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
