/**
 * \file    test_edhoc_handshake.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC handshake unit tests for EDHOC traces (RFC 9529) for chapter 2.
 * \version 0.2
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_EDHOC_HANDSHAKE_H
#define TEST_EDHOC_HANDSHAKE_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - call only edhoc_message_1_compose.
 *        - verify:
 *          - generated message 1.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state.
 *          - ephemeral DH private key value and length.
 */
void test_edhoc_handshake_message_1_compose(void);

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - call only edhoc_message_1_process.
 *        - verify:
 *          - if message 1 has been processed successfully.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state.
 *          - C_I value and length.
 *          - peer ephemeral DH public key value and length.
 */
void test_edhoc_handshake_message_1_process(void);

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - do required injections.
 *        - call only edhoc_message_2_compose.
 *        - verify:
 *          - generated message 2.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state, value and length.
 *          - computed DH key agreement.
 */
void test_edhoc_handshake_message_2_compose(void);

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - do required injections.
 *        - call only edhoc_message_2_process.
 *        - verify:
 *          - if message 2 has been processed successfully.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state, value and length.
 *          - computed DH key agreement.
 *          - C_R value and length.
 */
void test_edhoc_handshake_message_2_process(void);

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - do required injections.
 *        - call only edhoc_message_3_compose.
 *        - verify:
 *          - generated message 3.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state, value and length.
 */
void test_edhoc_handshake_message_3_compose(void);

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - do required injections.
 *        - call only edhoc_message_3_process.
 *        - verify:
 *          - if message 3 has been processed successfully.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state, value and length.
 */
void test_edhoc_handshake_message_3_process(void);

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - do required injections.
 *        - call only edhoc_message_4_compose.
 *        - verify:
 *          - generated message 4.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state, value and length.
 */
void test_edhoc_handshake_message_4_compose(void);

/**
 * \brief Test scenario:
 *        - use test vector as input for EDHOC context.
 *        - do required injections.
 *        - call only edhoc_message_4_process.
 *        - verify:
 *          - if message 4 has been processed successfully.
 *          - internal context fields.
 *          - TH state, value and length.
 *          - PRK state, value and length.
 */
void test_edhoc_handshake_message_4_process(void);

/**
 * \brief Test scenario:
 *        1) use test vector as input for EDHOC context's.
 *        2) perform full EDHOC handshake:
             (message 1 -> message 2 -> mesage 3 -> message 4)
 *           - value and lengthverify with test vector:
 *             - context.
 *             - TH.
 *             - PRK.
 *             - DH key agreement.
 *             - C_I / C_R.
 *        3) export OSCORE sessions:
 *           - verify with test vector:
 *             - internal context.
 *             - master secret.
 *             - master salt.
 *             - sender ID.
 *             - recipient ID.
 *        4) perform key update on EDHOC session
 *           - verify with test vector:
 *             - internal context.
 *             - PRK state,.
 *        5) export new OSCORE sessions:
 *           - verify with test vector:
 *             - internal context.
 *             - master secret.
 *             - master salt.
 *             - sender ID.
 *             - recipient ID.
 */
void test_edhoc_handshake_e2e(void);

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
void test_edhoc_handshake_e2e_real_crypto(void);

#endif /* TEST_EDHOC_HANDSHAKE_H */
