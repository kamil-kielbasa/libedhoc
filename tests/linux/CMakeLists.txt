# =============================================================================
# tests/linux — Unity + CTest module tests, one small binary per suite/scenario.
#
# A preset selects the configuration; each binary is guarded by the capability
# it needs and drops out when its cipher suite is disabled.
# =============================================================================

# sources.cmake defines LIBEDHOC_ROOT_DIR, so it must be located by a path
# relative to this file.
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/sources.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/edhoc_tests.cmake)

add_subdirectory(unit)
add_subdirectory(cipher_suites)
add_subdirectory(integration)
add_subdirectory(rfc9529)
add_subdirectory(robustness)

edhoc_assert_registry_nonempty()
edhoc_reconcile_linux_tree(${CMAKE_CURRENT_SOURCE_DIR})
