# =============================================================================
# tests/linux/cipher_suites — one standalone Unity binary per reference suite.
#
# Each binary is guarded by its suite's CONFIG_..._ENABLE, so the active preset
# decides which suites exist and each binary self-qualifies (capability model).
# Buffer isolation (problem #1) comes from the preset's generated edhoc_config.h,
# not from which sources link: a p256 preset sizes every binary for P-256, never
# for ML-KEM-512. The tests call the suite dispatcher
# (edhoc_cipher_suite_get_crypto/params), so each binary links the preset's
# enabled cipher-suite sources (dispatcher + suites) via
# ${LIBEDHOC_CIPHER_SUITE_SOURCES}.
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
    # The ML-DSA-44 vector header sits next to the test source; quote-include
    # finds it automatically.
    edhoc_add_unity_test(
        NAME          test_cipher_suite_pqc_1
        SOURCES       cipher_suite_pqc_1/test_cipher_suite_pqc_1.c ${_driver}
        SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        INCLUDE       ${_drv}
        GROUPS        cipher_suite_pqc_1_positive cipher_suite_pqc_1_negative)
endif()
