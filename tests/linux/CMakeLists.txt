# =============================================================================
# tests/linux — Unity + CTest module tests, one small binary per suite/scenario.
#
# Categories are fully isolated from each other (each keeps its own support/
# helpers); binaries within a category may share that category's helpers. A
# preset selects the config (suite/backend/buffer floor); each binary is guarded
# by the capability it needs and self-qualifies out when its suite is disabled.
# =============================================================================

# sources.cmake defines LIBEDHOC_ROOT_DIR (and every source/include list), so it
# must be located by a path relative to this file, not via that variable.
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/sources.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/edhoc_tests.cmake)

add_subdirectory(cipher_suites)
add_subdirectory(integration)
add_subdirectory(rfc9529)
add_subdirectory(robustness)

# Anti-silent-skip net #1: a tests-enabled preset that registered nothing means
# no suite was enabled — fail the configure loudly rather than pass vacuously.
edhoc_assert_registry_nonempty()

# Anti-silent-skip net #1 (orphan reconcile): in an all-suites build, every
# test_*.c must be wired into a binary. Catches a test file added to the tree
# but never referenced by a CMakeLists.
edhoc_reconcile_linux_tree(${CMAKE_CURRENT_SOURCE_DIR})
