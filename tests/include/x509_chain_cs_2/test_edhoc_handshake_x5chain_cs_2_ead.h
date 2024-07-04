/**
 * \file    test_edhoc_handshake_x5chain_cs_2_ead.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC handshake unit test for X.509 chain authentication method
 *          for cipher suite 2 with multiple EAD tokens.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_HANDSHAKE_X5CHAIN_CS_2_EAD_H
#define TEST_EDHOC_HANDSHAKE_X5CHAIN_CS_2_EAD_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Test scenario:
 *        1) use test vector as input for EDHOC context's.
 *        2) perform full EDHOC handshake:
 *           (message 1 -> message 2 -> mesage 3 -> message 4)
 *           - verify:
 *             - internal context.
 *             - TH state.
 *             - PRK state.
 *             - DH key agreement.
 *             - C_I / C_R.
 *             - EAD.
 *        3) export OSCORE sessions:
 *           - verify by cross-check:
 *             - internal context.
 *             - master secret.
 *             - master salt.
 *             - sender ID.
 *             - recipient ID.
 *        4) perform key update on EDHOC session
 *           - verify:
 *             - internal context.
 *             - PRK state.
 *        5) export new OSCORE sessions:
 *           - verify by cross-check:
 *             - internal context.
 *             - master secret.
 *             - master salt.
 *             - sender ID.
 *             - recipient ID.
 */
void test_edhoc_handshake_x5chain_cs_2_single_cert_e2e_multiple_ead_tokens(void);

#endif /* TEST_EDHOC_HANDSHAKE_X5CHAIN_CS_2_EAD_H */
