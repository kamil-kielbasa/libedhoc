/**
 * \file    test_edhoc_handshake_x5chain.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC handshake unit test for X.509 chain authentication method
 *          with real crypto usage.
 * \version 0.2
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_HANDSHAKE_X5CHAIN_H
#define TEST_EDHOC_HANDSHAKE_X5CHAIN_H

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
 *
 * \note "real crypto" means that ephemeral Diffie-Hellman per each run will
 *       generate different keys. This is why only cross-check is possible as
 *       verification step.
 */
void test_edhoc_handshake_x5chain_e2e_real_crypto(void);

#endif /* TEST_EDHOC_HANDSHAKE_X5CHAIN_H */
