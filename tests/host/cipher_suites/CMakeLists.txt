# =============================================================================
# tests/host/cipher_suites — one standalone Unity binary per reference suite.
#
# Each binary is guarded by its suite's CONFIG_..._ENABLE and links the enabled
# cipher-suite sources, because the tests go through the suite dispatcher.
# =============================================================================

# Shared driver: the cipher_suite_descriptor plus the cipher_suite_test_* crypto
# routines. Each suite's test file is a thin descriptor that links this driver.
set(_drv ${CMAKE_CURRENT_SOURCE_DIR}/driver)
set(_driver
    ${_drv}/cipher_suite_driver.c
    ${_drv}/cipher_suite_test_getters.c
    ${_drv}/cipher_suite_test_key_exchange.c
    ${_drv}/cipher_suite_test_sign_verify.c
    ${_drv}/cipher_suite_test_kdf.c
    ${_drv}/cipher_suite_test_aead.c
    ${_drv}/cipher_suite_test_hash.c)

if(CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_0
        SOURCES       cipher_suite_0/test_cipher_suite_0.c ${_driver}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv}
        GROUPS        cipher_suite_0_positive cipher_suite_0_negative)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_2
        SOURCES       cipher_suite_2/test_cipher_suite_2.c ${_driver}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv}
        GROUPS        cipher_suite_2_positive cipher_suite_2_negative)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_4
        SOURCES       cipher_suite_4/test_cipher_suite_4.c ${_driver}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv}
        GROUPS        cipher_suite_4_positive cipher_suite_4_negative)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_24
        SOURCES       cipher_suite_24/test_cipher_suite_24.c ${_driver}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv}
        GROUPS        cipher_suite_24_positive cipher_suite_24_negative)
endif()

if(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE)
    edhoc_add_unity_test(
        NAME          test_cipher_suite_pqc_1
        SOURCES       cipher_suite_pqc_1/test_cipher_suite_pqc_1.c ${_driver}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv}
        GROUPS        cipher_suite_pqc_1_positive cipher_suite_pqc_1_negative)
endif()
