/**
 * \file    test_edhoc_handshake_ead_1.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC EAD handshake unit tests for EDHOC traces (RFC 9529) for chapter 2.
 * \version 0.5
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_HANDSHAKE_EAD_1_H
#define TEST_EDHOC_HANDSHAKE_EAD_1_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Test scenario:
 *        1) perform full EDHOC handshake
 *           (message 1 -> message 2 -> mesage 3 -> message 4).
 *        2) use EAD compose and process with only single token.
 *        3) verify after each EAD compose and process:
 *           - label.
 *           - value length and value.
 *        3) export OSCORE sessions:
 *           - verify by cross-check:
 *             - internal context.
 *             - master secret.
 *             - master salt.
 *             - sender ID.
 *             - recipient ID.
 */
void test_edhoc_handshake_1_e2e_single_ead_token(void);

/**
 * \brief Test scenario:
 *        1) perform full EDHOC handshake
 *           (message 1 -> message 2 -> mesage 3 -> message 4).
 *        2) use EAD compose and process with many tokens.
 *        3) verify after each EAD compose and process:
 *           - label.
 *           - value length and value.
 *        3) export OSCORE sessions:
 *           - verify by cross-check:
 *             - internal context.
 *             - master secret.
 *             - master salt.
 *             - sender ID.
 *             - recipient ID.
 */
void test_edhoc_handshake_1_e2e_multiple_ead_tokens(void);

#endif /* TEST_EDHOC_HANDSHAKE_EAD_1_H */
