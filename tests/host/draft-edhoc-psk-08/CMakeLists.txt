# =============================================================================
# tests/host/draft-edhoc-psk-08 — EDHOC-PSK test vectors, Appendix B.
#
# The vectors replay cipher suite 2, so the binary is guarded by that suite.
# =============================================================================

set(_sup ${CMAKE_CURRENT_SOURCE_DIR}/support)

# Under the custom backend every binary must supply edhoc_mem_alloc/free.
set(_memhook "")
if(CONFIG_LIBEDHOC_MEM_BACKEND EQUAL 2)
    set(_memhook ${_sup}/test_mem_default.c)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    edhoc_add_unity_test(
        NAME          test_draft_edhoc_psk_08
        SOURCES       test_draft_edhoc_psk_08.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        draft_edhoc_psk_08)
endif()
