# =============================================================================
# tests/host/robustness/oom_sweep — custom-backend out-of-memory sweep.
#
# An instrumented allocator drives a suite-0 handshake and fails the nth
# allocation for every n, proving the library releases every buffer it acquired
# on each failure path. Needs a controllable allocator, hence the guards below.
# =============================================================================

# CONFIG_LIBEDHOC_MEM_BACKEND: 2 = custom.
set(_mem_backend_custom 2)

# These guards are the single source of truth: the sources carry no #if.
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
