/**
 * \file    test_edhoc_error_message.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC error message unit tests.
 * \version 0.5
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_ERROR_MESSAGE_H
#define TEST_EDHOC_ERROR_MESSAGE_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Test EDHOC error message - success.
 */
void test_edhoc_error_message_success(void);

/**
 * \brief Test EDHOC error message - unspecified error.
 */
void test_edhoc_error_message_unspecified_error(void);

/**
 * \brief Test EDHOC error message - wrong selected cipher suite.
 */
void test_edhoc_error_message_wrong_selected_cipher_suite_one(void);

/**
 * \brief Test EDHOC error message - wrong selected cipher suites.
 */
void test_edhoc_error_message_wrong_selected_cipher_suite_many(void);

/**
 * \brief Test EDHOC error message - unknown credential referenced.
 */
void test_edhoc_error_message_unknown_credential_referenced(void);

#endif /* TEST_EDHOC_ERROR_MESSAGE_H */
