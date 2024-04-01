/**
 * @file    test_edhoc_x509_hash.h
 * @author  Kamil Kielbasa
 * @brief   Unit test for EDHOC (authentication via X509 hash).
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_X509_HASH_H
#define TEST_EDHOC_X509_HASH_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * @brief Unit test for EDHOC message 1 compose for X509 hash.
 */
void test_edhoc_x509_hash_message_1_compose(void);

/**
 * @brief Unit test for EDHOC message 1 process for X509 hash.
 */
void test_edhoc_x509_hash_message_1_process(void);

/**
 * @brief Unit test for EDHOC message 2 compose for X509 hash.
 */
void test_edhoc_x509_hash_message_2_compose(void);

/**
 * @brief Unit test for EDHOC message 2 process for X509 hash.
 */
void test_edhoc_x509_hash_message_2_process(void);

/**
 * @brief Unit test for EDHOC message 3 compose for X509 hash.
 */
void test_edhoc_x509_hash_message_3_compose(void);

/**
 * @brief Unit test for EDHOC message 3 process for X509 hash.
 */
void test_edhoc_x509_hash_message_3_process(void);

/**
 * @brief Unit test for all EDHOC compose and process functions for X509 hash.
 *        Verified each of message compose and process step, transcript hashes
 *        and pseudo random keys and lastly shared secret. Mocked ECDH and ECDSA.
 */
void test_edhoc_x509_hash_edhoc_e2e(void);

/**
 * @brief Unit test for all EDHOC compose and process functions (X509 hash).
 *        Using real crypto allows to verify only shared secret.
 */
void test_edhoc_x509_hash_edhoc_e2e_real_crypto(void);

#endif /* TEST_EDHOC_X509_HASH_H */