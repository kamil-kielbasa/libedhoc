# =============================================================================
# Pluggable backends. Each backend is its own target with a namespaced alias.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

# --- CBOR backend (compiled) -------------------------------------------------
add_library(backend_cbor STATIC ${LIBEDHOC_BACKEND_CBOR_SOURCES})
add_library(libedhoc::backend_cbor ALIAS backend_cbor)

# zcbor types appear in this backend's public headers, hence PUBLIC.
target_link_libraries(backend_cbor PUBLIC zcbor)
target_include_directories(backend_cbor SYSTEM PUBLIC
    $<BUILD_INTERFACE:${LIBEDHOC_BACKEND_CBOR_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

set_target_properties(backend_cbor PROPERTIES EXPORT_NAME backend_cbor)

# Attacker-controlled bytes reach this backend first, so it has to carry the
# same instrumentation as the core. Without it a decoder overrun goes unreported
# and libFuzzer gets no coverage signal from the CBOR model.
if(LIBEDHOC_ENABLE_SANITIZERS)
    target_compile_options(backend_cbor PRIVATE
                           -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(backend_cbor PUBLIC -fsanitize=address,undefined)
endif()

if(LIBEDHOC_ENABLE_FUZZING)
    target_compile_options(backend_cbor PRIVATE
                           -fsanitize=fuzzer-no-link,address,undefined
                           -fno-omit-frame-pointer)
    target_link_options(backend_cbor PUBLIC -fsanitize=address,undefined)
endif()

# --- Memory backend (header-only) --------------------------------------------
add_library(backend_memory INTERFACE)
add_library(libedhoc::backend_memory ALIAS backend_memory)
target_include_directories(backend_memory INTERFACE
    $<BUILD_INTERFACE:${LIBEDHOC_BACKEND_MEM_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

set_target_properties(backend_memory PROPERTIES EXPORT_NAME backend_memory)

# --- Log backend (header-only) -----------------------------------------------
add_library(backend_log INTERFACE)
add_library(libedhoc::backend_log ALIAS backend_log)
target_include_directories(backend_log INTERFACE
    $<BUILD_INTERFACE:${LIBEDHOC_BACKEND_LOG_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

set_target_properties(backend_log PROPERTIES EXPORT_NAME backend_log)
