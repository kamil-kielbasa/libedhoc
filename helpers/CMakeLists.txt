# =============================================================================
# libedhoc::helpers — convenience helpers (cipher-suite glue, test vectors).
#
# The helper sources are compiled by the consumer (tests, samples, downstream
# applications), so this is an INTERFACE target that only carries usage
# requirements: the helper headers plus the backends those headers pull in.
# A consumer that compiles the helper sources inherits the right include paths
# by linking this target.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

add_library(libedhoc_helpers INTERFACE)
add_library(libedhoc::helpers ALIAS libedhoc_helpers)

target_include_directories(libedhoc_helpers INTERFACE
    $<BUILD_INTERFACE:${LIBEDHOC_HELPERS_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# Helpers include edhoc_backend_log.h and the CBOR backend headers, and call
# the public API — so consumers of the helpers need all three.
target_link_libraries(libedhoc_helpers INTERFACE
    libedhoc::api
    libedhoc::backend_cbor
    libedhoc::backend_log)

# The .c files themselves, exposed so consumers can compile them without
# hard-coding helpers/src paths (used by the install block).
set(LIBEDHOC_HELPERS_SOURCES ${LIBEDHOC_HELPERS_SOURCES} PARENT_SCOPE)

set_target_properties(libedhoc_helpers PROPERTIES EXPORT_NAME helpers)
