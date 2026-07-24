# =============================================================================
# tests/linux/integration — one standalone Unity binary per handshake scenario.
#
# PR1 migrates these as-is (per-scenario binaries); the shared handshake driver
# that de-duplicates them arrives in a later PR. Each binary links only the
# cipher-suite sources the active preset enables (${LIBEDHOC_CIPHER_SUITE_SOURCES}),
# and is guarded by the suite / backend it exercises so it self-qualifies out
# under presets that disable that capability.
# =============================================================================

set(_sup ${CMAKE_CURRENT_SOURCE_DIR}/support)

# When the post-quantum suite is enabled its reference source lands in
# ${LIBEDHOC_CIPHER_SUITE_SOURCES}, so every binary compiling that list needs
# liboqs + XKCP wired. In the single-suite matrix pqc is enabled alone, so this
# only ever fires for the pqc handshake binary.
set(_pqc "")
if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
    set(_pqc PQC)
endif()

# Under the custom backend every binary must supply edhoc_mem_alloc/free. The
# mem_custom binary brings its own instrumented hooks; everything else links the
# plain default allocator (empty string, so a no-op, under stack/heap).
set(_memhook "")
if(CONFIG_LIBEDHOC_MEM_BACKEND EQUAL 2)
    set(_memhook ${_sup}/test_mem_default.c)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    edhoc_add_unity_test(
        NAME          test_handshake_x5chain_sig_suite0
        SOURCES       test_handshake_x5chain_sig_suite0.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_x5chain_sig_suite0
        ${_pqc})
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    edhoc_add_unity_test(
        NAME          test_handshake_x5chain_sig_suite2
        SOURCES       test_handshake_x5chain_sig_suite2.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_x5chain_sig_suite2
        ${_pqc})

    edhoc_add_unity_test(
        NAME          test_handshake_x5chain_dh_suite2
        SOURCES       test_handshake_x5chain_dh_suite2.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_x5chain_dh_suite2
        ${_pqc})

    edhoc_add_unity_test(
        NAME          test_handshake_x5t_sig_suite2
        SOURCES       test_handshake_x5t_sig_suite2.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_x5t_sig_suite2
        ${_pqc})

    edhoc_add_unity_test(
        NAME          test_handshake_auth_methods
        SOURCES       test_handshake_auth_methods.c
                      ${_sup}/test_ead.c
                      ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_auth_methods
        ${_pqc})

    edhoc_add_unity_test(
        NAME          test_handshake_handle_balance
        SOURCES       test_handshake_handle_balance.c
                      ${_sup}/test_ead.c
                      ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_handle_balance
        ${_pqc})
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE)
    edhoc_add_unity_test(
        NAME          test_handshake_x5chain_sig_suite24
        SOURCES       test_handshake_x5chain_sig_suite24.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_x5chain_sig_suite24
        ${_pqc})
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
    edhoc_add_unity_test(
        NAME          test_handshake_x5chain_sig_suite_pqc_1
        SOURCES       test_handshake_x5chain_sig_suite_pqc_1.c ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        handshake_x5chain_sig_suite_pqc_1
        PQC)
endif()

# Custom-backend out-of-memory handshake: the source is #if-guarded to the
# custom backend, so its TEST_GROUP only exists there — guard the binary to
# match, else the generated runner references an undefined group.
if(CONFIG_LIBEDHOC_MEM_BACKEND EQUAL 2 AND CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    edhoc_add_unity_test(
        NAME          test_handshake_mem_custom
        SOURCES       test_handshake_mem_custom.c
                      ${_sup}/test_mem_custom.c
                      ${_sup}/test_mem_custom_handshake.c
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_sup}
        GROUPS        mem_custom_handshake
        ${_pqc})
endif()
