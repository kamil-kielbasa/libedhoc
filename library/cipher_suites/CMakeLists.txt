# =============================================================================
# libedhoc::cipher_suites — reference cipher-suite implementations.
#
# The reference sources are compiled by the consumer, so this INTERFACE target
# only carries the include paths and backends those sources need.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/sources.cmake)

add_library(libedhoc_cipher_suites INTERFACE)
add_library(libedhoc::cipher_suites ALIAS libedhoc_cipher_suites)

target_include_directories(libedhoc_cipher_suites INTERFACE
    "$<BUILD_INTERFACE:${LIBEDHOC_CIPHER_SUITE_INCLUDE_DIRS}>"
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# The reference sources include the log and CBOR backend headers and call the
# public API.
target_link_libraries(libedhoc_cipher_suites INTERFACE
    libedhoc::api
    libedhoc::backend_cbor
    libedhoc::backend_log)

# Exposed so the install block can ship the sources without re-deriving paths.
set(LIBEDHOC_CIPHER_SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES} PARENT_SCOPE)

set_target_properties(libedhoc_cipher_suites PROPERTIES EXPORT_NAME cipher_suites)
