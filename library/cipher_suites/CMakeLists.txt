# =============================================================================
# libedhoc::cipher_suites — reference cipher-suite implementations.
#
# The reference sources are compiled by the consumer (tests, samples, downstream
# applications), so this is an INTERFACE target that only carries usage
# requirements: the per-suite headers plus the backends those headers pull in.
# A consumer that compiles the reference sources inherits the right include
# paths by linking this target.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/sources.cmake)

add_library(libedhoc_cipher_suites INTERFACE)
add_library(libedhoc::cipher_suites ALIAS libedhoc_cipher_suites)

target_include_directories(libedhoc_cipher_suites INTERFACE
    "$<BUILD_INTERFACE:${LIBEDHOC_CIPHER_SUITE_INCLUDE_DIRS}>"
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# Reference suites include edhoc_backend_log.h and the CBOR backend headers,
# and call the public API — so consumers need all three.
target_link_libraries(libedhoc_cipher_suites INTERFACE
    libedhoc::api
    libedhoc::backend_cbor
    libedhoc::backend_log)

# The .c files themselves, exposed so consumers can compile them without
# hard-coding cipher_suites paths (used by the install block).
set(LIBEDHOC_CIPHER_SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES} PARENT_SCOPE)

set_target_properties(libedhoc_cipher_suites PROPERTIES EXPORT_NAME cipher_suites)
