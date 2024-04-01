/**
 * @file    test_mbedtls_crypto.h
 * @author  Kamil Kielbasa
 * @brief   Unit test for PSA crypto functions (mbedtls backend).
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_MBEDTLS_CRYPTO_H
#define TEST_MBEDTLS_CRYPTO_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * @brief Unit test for AEAD (AES-CCM-16-64-128).
 */
void test_mbedtls_crypto_aead(void);

/**
 * @brief Unit test for ECDSA (P-256).
 */
void test_mbedtls_crypto_ecdsa(void);

/**
 * @brief Unit test for ECDH (P-256).
 */
void test_mbedtls_crypto_ecdh(void);

/**
 * @brief Unit test for HKDF extract & expand (HMAC-SHA-256).
 */
void test_mbedtls_crypto_hkdf(void);

/**
 * @brief Unit test for hash (SHA-256).
 */
void test_mbedtls_crypto_hash(void);

#endif /* TEST_MBEDTLS_CRYPTO_H */