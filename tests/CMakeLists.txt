# =============================================================================
# tests/ — libedhoc test tree.
#
# Standalone tests live under host/, the Zephyr tests under zephyr/ (built by
# twister, not from here).
# =============================================================================

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

add_subdirectory(host)
