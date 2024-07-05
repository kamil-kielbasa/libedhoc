/**
 * \file    test_cipher_suite_2.h
 * \author  Kamil Kielbasa
 * \brief   Unit tests for cipher suite 2.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_CIPHER_SUITE_2_H
#define TEST_CIPHER_SUITE_2_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Unit test for ECDSA (ES256).
 */
void test_cipher_suite_2_ecdsa(void);

/**
 * \brief Unit test for ECDH (P-256).
 */
void test_cipher_suite_2_ecdh(void);

/**
 * \brief Unit test for HKDF extract & expand (HMAC-SHA-256).
 */
void test_cipher_suite_2_hkdf(void);

/**
 * \brief Unit test for AEAD (AES-CCM-16-64-128).
 */
void test_cipher_suite_2_aead(void);

/**
 * \brief Unit test for hash (SHA-256).
 */
void test_cipher_suite_2_hash(void);

#endif /* TEST_CIPHER_SUITE_2_H */
