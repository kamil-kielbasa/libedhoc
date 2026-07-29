# =============================================================================
# tests/linux/integration — one standalone Unity binary per cipher suite and
# credential type; each EDHOC method is a TEST case inside its binary.
#
# Every scenario is a thin descriptor that drives the shared handshake driver
# (driver/); its credentials are the real X.509 test vectors (test_vectors/).
# Each binary is guarded by the cipher suite it exercises. liboqs + XKCP are
# linked automatically for the post-quantum suite (see edhoc_add_unity_test).
# =============================================================================

# CONFIG_LIBEDHOC_MEM_BACKEND: 2 = custom.
set(_mem_backend_custom 2)

# The custom backend needs a link-time allocator (a no-op TU under stack/heap);
# the instrumented one lives with the robustness tests.
set(_memhook "")
if(CONFIG_LIBEDHOC_MEM_BACKEND EQUAL _mem_backend_custom)
    set(_memhook ${CMAKE_CURRENT_SOURCE_DIR}/driver/handshake_mem_default.c)
endif()

# Shared driver: run_handshake() plus the generic credential / EAD callbacks.
set(_drv ${CMAKE_CURRENT_SOURCE_DIR}/driver)
set(_driver
    ${_drv}/handshake_driver.c
    ${_drv}/handshake_credentials.c
    ${_drv}/handshake_ead.c)

set(_vectors ${CMAKE_CURRENT_SOURCE_DIR}/test_vectors)

if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_0_x509_chain
        SOURCES       test_cipher_suite_0_x509_chain.c ${_driver} ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv} ${_vectors}
        GROUPS        cipher_suite_0_x509_chain)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_2_x509_chain
        SOURCES       test_cipher_suite_2_x509_chain.c ${_driver} ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv} ${_vectors}
        GROUPS        cipher_suite_2_x509_chain)

    edhoc_add_unity_test(
        NAME          test_cipher_suite_2_x509_hash
        SOURCES       test_cipher_suite_2_x509_hash.c ${_driver} ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv} ${_vectors}
        GROUPS        cipher_suite_2_x509_hash)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_4_x509_chain
        SOURCES       test_cipher_suite_4_x509_chain.c ${_driver} ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv} ${_vectors}
        GROUPS        cipher_suite_4_x509_chain)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_24_x509_chain
        SOURCES       test_cipher_suite_24_x509_chain.c ${_driver} ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv} ${_vectors}
        GROUPS        cipher_suite_24_x509_chain)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_pqc_1_x509_chain
        SOURCES       test_cipher_suite_pqc_1_x509_chain.c ${_driver} ${_memhook}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv} ${_vectors}
        GROUPS        cipher_suite_pqc_1_x509_chain)
endif()
