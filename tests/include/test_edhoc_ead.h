/**
 * @file    test_edhoc_ead.h
 * @author  Kamil Kielbasa
 * @brief   Unit test for EDHOC EAD compose & process.
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_EAD_H
#define TEST_EDHOC_EAD_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * @brief Unit test for EDHOC single EAD token compose and process.
 */
void test_edhoc_single_ead_token(void);

/**
 * @brief Unit test for EDHOC multiple EAD tokens compose and process.
 */
void test_edhoc_multiple_ead_tokens(void);

#endif /* TEST_EDHOC_EAD_H */