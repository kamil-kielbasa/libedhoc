# =============================================================================
# tests/ — libedhoc Linux test tree.
#
# Every test lives under tests/linux/ as a standalone, per-suite/per-scenario
# Unity binary (unit, cipher_suites, integration, rfc9529, robustness), each
# sized by the active preset — this is what solves the single-binary
# buffer-inflation problem. sources.cmake defines the shared source/include
# lists those binaries draw on.
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

add_subdirectory(linux)
