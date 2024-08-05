/**
 * \file    test_edhoc_cipher_suite_negotiation.h
 * \author  Kamil Kielbasa
 * \brief   Test scenarios for cipher suite negotiation.
 * \version 0.5
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_CIPHER_SUITE_NEGOTIATION_H
#define TEST_EDHOC_CIPHER_SUITE_NEGOTIATION_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Cipher suite negotiation for scenario:
 *        - RFC 9528: 6.3.2. Examples:
 *          - Figure 8: Cipher Suite Negotiation Example 1.
 */
void test_edhoc_cipher_suites_negotiation_scenario_1(void);

/**
 * \brief Cipher suite negotiation for scenario:
 *        - RFC 9528: 6.3.2. Examples:
 *          - Figure 9: Cipher Suite Negotiation Example 2.
 */
void test_edhoc_cipher_suites_negotiation_scenario_2(void);

#endif /* TEST_EDHOC_CIPHER_SUITE_NEGOTIATION_H */
