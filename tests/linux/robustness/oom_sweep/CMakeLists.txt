# =============================================================================
# tests/linux/robustness/oom_sweep — custom-backend out-of-memory sweep.
#
# An instrumented allocator drives a suite-0 handshake and fails the nth
# allocation for every n, proving the library releases every previously acquired
# buffer on each failure path. It needs a controllable allocator, so it builds
# only under the custom memory backend and brings its own hooks — it does not
# use the shared integration driver.
#
# The suite-0 credentials are a static local copy of the integration
# cipher_suite_0 test vector (test_vector/).
# =============================================================================

# CONFIG_LIBEDHOC_MEM_BACKEND selects the allocator (Kconfig): 0 = stack,
# 1 = heap, 2 = custom. Name the custom value so the guard below reads clearly.
set(_mem_backend_custom 2)

# The sources compile only under the custom backend and a suite-0 build. The
# CMake guards below are the single source of truth for that — the sources no
# longer carry an #if of their own.
if(CONFIG_LIBEDHOC_MEM_BACKEND EQUAL _mem_backend_custom)
    if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
        edhoc_add_unity_test(
            NAME          test_mem_custom
            SOURCES       test_mem_custom.c
                          test_mem_custom_handshake.c
                          test_mem_custom_group.c
            SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
            INCLUDE       ${CMAKE_CURRENT_SOURCE_DIR}
GROUPS        mem_custom_handshake)
    endif()
endif()
