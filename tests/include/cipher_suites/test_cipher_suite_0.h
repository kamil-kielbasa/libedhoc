/**
 * \file    test_cipher_suite_0.h
 * \author  Kamil Kielbasa
 * \brief   Unit tests for cipher suite 0.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_CIPHER_SUITE_0_H
#define TEST_CIPHER_SUITE_0_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Unit test for ECDSA (EdDSA).
 */
void test_cipher_suite_0_ecdsa(void);

/**
 * \brief Unit test for ECDH (X25519).
 */
void test_cipher_suite_0_ecdh(void);

/**
 * \brief Unit test for HKDF extract & expand (HMAC-SHA-256).
 */
void test_cipher_suite_0_hkdf(void);

/**
 * \brief Unit test for AEAD (AES-CCM-16-64-128).
 */
void test_cipher_suite_0_aead(void);

/**
 * \brief Unit test for hash (SHA-256).
 */
void test_cipher_suite_0_hash(void);

#endif /* TEST_CIPHER_SUITE_0_H */
