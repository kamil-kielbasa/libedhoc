/**
 * \file    handshake_ead.h
 * \author  Kamil Kielbasa
 * \brief   Generic External Authorization Data (EAD) callbacks for the
 *          handshake driver.
 *
 *          A scenario describes the EAD tokens expected on each EDHOC message
 *          in one \ref hs_ead table (shared by both peers). \ref hs_ead_compose
 *          emits the tokens for the message being sent; \ref hs_ead_process
 *          checks that the received tokens match the table exactly (label,
 *          length and value) and returns an EDHOC error on mismatch, letting
 *          the library abort the session so the failure surfaces at the driver.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef HANDSHAKE_EAD_H
#define HANDSHAKE_EAD_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (for CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* EDHOC header: */
#include <edhoc/ead.h>

/* Standard library headers: */
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */

/** \brief Number of EDHOC messages that may carry EAD (message 1..4). */
#define HS_EAD_MESSAGE_COUNT ((size_t)4)

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief The EAD tokens expected on a single EDHOC message.
 *
 *        Tokens are referenced, so a scenario declares each one as a
 *        \c static \c const \ref edhoc_ead_token and lists pointers here.
 */
struct hs_ead_message {
	/** Expected tokens, referenced (not owned) by the scenario. */
	const struct edhoc_ead_token
		*token[CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS];
	/** Number of valid entries in \p token. */
	size_t token_count;
};

/**
 * \brief EAD tokens per EDHOC message, indexed by \ref edhoc_message.
 *
 *        The same table is bound to both peers: each side only composes its own
 *        messages and verifies the messages it receives, so one shared
 *        description is unambiguous.
 */
struct hs_ead {
	/** Expected tokens per message, indexed by \ref edhoc_message
	 *  (\c EDHOC_MESSAGE_1 .. \c EDHOC_MESSAGE_4). */
	struct hs_ead_message message[HS_EAD_MESSAGE_COUNT];
};

/* Module interface function declarations ---------------------------------- */

/**
 * \brief Compose callback: emit the tokens the table lists for the message
 *        named by \p call_context.
 */
int hs_ead_compose(void *user_context,
		   const struct edhoc_call_context *call_context,
		   struct edhoc_ead_token *ead_token, size_t ead_token_size,
		   size_t *ead_token_count);

/**
 * \brief Process callback: return an error unless the received tokens match
 *        the table for the message named by \p call_context (label, length and
 *        value).
 */
int hs_ead_process(void *user_context,
		   const struct edhoc_call_context *call_context,
		   const struct edhoc_ead_token *ead_token,
		   size_t ead_token_size);

#endif /* HANDSHAKE_EAD_H */
