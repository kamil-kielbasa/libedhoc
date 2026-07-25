# =============================================================================
# tests/linux/rfc9529 — RFC 9529 trace vectors + RFC 9528 suite negotiation.
#
# rfc9528_negotiation is folded in here (it is a negotiation trace, suite 2).
# chapter2 drives the dispatcher for suite 0, chapter3 for suite 2, so each
# binary is guarded by the suite it replays and links the preset's enabled
# cipher-suite sources.
# =============================================================================

set(_sup ${CMAKE_CURRENT_SOURCE_DIR}/support)

# Under the custom backend every binary must supply edhoc_mem_alloc/free.
set(_memhook "")
if(CONFIG_LIBEDHOC_MEM_BACKEND EQUAL 2)
    set(_memhook ${_sup}/test_mem_default.c)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    edhoc_add_unity_test(
        NAME          test_rfc9529_chapter2
        SOURCES       test_rfc9529_chapter2.c
                      ${_sup}/test_ead.c
                      ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        rfc9529_chapter2)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    edhoc_add_unity_test(
        NAME          test_rfc9529_chapter3
        SOURCES       test_rfc9529_chapter3.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        rfc9529_chapter3)

    edhoc_add_unity_test(
        NAME          test_rfc9528_negotiation
        SOURCES       test_rfc9528_negotiation.c
                      ${_sup}/test_credentials.c
                      ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        rfc9528_negotiation)
endif()
