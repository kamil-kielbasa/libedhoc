/**
 * \file    test_mem_custom_handshake.h
 * \author  Kamil Kielbasa
 * \brief   Shared cipher suite 0 handshake harness for the custom memory
 *          backend tests. It provisions a pair of contexts and drives a full
 *          M1->M2->M3->M4 handshake, exporting and cross-checking the OSCORE
 *          session on the success path so that the unit and integration tests
 *          share a single, audited code path.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_MEM_CUSTOM_HANDSHAKE_H
#define TEST_MEM_CUSTOM_HANDSHAKE_H

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include <edhoc.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

/**
 * \brief Initialise and provision both contexts for a suite-0 handshake.
 *
 * Performs no assertions of its own: like \ref test_mem_custom_drive_handshake
 * it is intentionally rc-returning so the calling test wraps the result in
 * ``TEST_ASSERT_*``.
 *
 * \param[out] initiator  Initiator context to set up.
 * \param[out] responder  Responder context to set up.
 *
 * \return EDHOC_SUCCESS on success, otherwise the first non-success code
 *         reported by any provisioning step.
 */
int test_mem_custom_setup_contexts(struct edhoc_context *initiator,
				   struct edhoc_context *responder);

/**
 * \brief Drive a full M1->M2->M3->M4 handshake and cross-check OSCORE.
 *
 * Runs the four message steps, then exports and cross-checks the OSCORE session
 * of both peers. The helper performs no assertions of its own: it is
 * intentionally rc-returning so the out-of-memory tests can inject an
 * allocation failure and observe the first failing step, while the calling
 * test wraps the result in ``TEST_ASSERT_*``.
 *
 * \param[in,out] initiator  Provisioned initiator context.
 * \param[in,out] responder  Provisioned responder context.
 *
 * \return EDHOC_SUCCESS when the handshake completes and both OSCORE sessions
 *         match, otherwise the first non-success code reported by any step.
 */
int test_mem_custom_drive_handshake(struct edhoc_context *initiator,
				    struct edhoc_context *responder);

#endif /* TEST_MEM_CUSTOM_HANDSHAKE_H */
