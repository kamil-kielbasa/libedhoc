# =============================================================================
# tests/ — libedhoc test tree.
#
# Linux tests live under linux/, the Zephyr under zephyr/ (built by
# twister, not from here).
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

add_subdirectory(linux)
