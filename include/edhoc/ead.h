/**
 * \file    ead.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC External Authorization Data (EAD) interface (RFC 9528: 3.8).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_EAD_H
#define EDHOC_EAD_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-ead EDHOC interface EAD
 * @{
 */

/**
 * \brief EDHOC message number, passed to the EAD callbacks to identify which
 *        message (EAD_1..EAD_4) is being composed or processed.
 */
enum edhoc_message {
	/** EDHOC message 1. */
	EDHOC_MESSAGE_1,
	/** EDHOC message 2. */
	EDHOC_MESSAGE_2,
	/** EDHOC message 3. */
	EDHOC_MESSAGE_3,
	/** EDHOC message 4. */
	EDHOC_MESSAGE_4,
};

/**
 * \brief A single EAD item: a label and an optional value (RFC 9528: 3.8).
 */
struct edhoc_ead_token {
	/** EAD label. A negative label marks the item as critical: if the peer
	 *  does not recognise it, EDHOC processing fails (RFC 9528: 3.8). */
	int32_t label;

	/** Optional EAD value buffer (may be NULL when \p value_length is 0). */
	const uint8_t *value;
	/** Size of the \p value buffer in bytes. */
	size_t value_length;
};

/**
 * \brief Bind structure for EAD operations.
 */
struct edhoc_ead {
	/**
	 * \brief Compose external authorization data (EAD) items.
	 *
	 * Called by the library while composing an outgoing message so the
	 * application can attach EAD items to it (RFC 9528: 3.8). Write zero or
	 * more items and set \p ead_token_count accordingly.
	 *
	 * \param[in] user_context      User context.
	 * \param message               Which message is being composed (EAD_1..EAD_4).
	 * \param[out] ead_token        Array to fill with the EAD items to send.
	 * \param ead_token_size        Capacity of the \p ead_token array in entries.
	 * \param[out] ead_token_count    On success, the number of items written.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*compose)(void *user_context, enum edhoc_message message,
		       struct edhoc_ead_token *ead_token, size_t ead_token_size,
		       size_t *ead_token_count);

	/**
	 * \brief Process received external authorization data (EAD) items.
	 *
	 * Called by the library while processing an incoming message to deliver
	 * the received EAD items to the application for validation (RFC 9528:
	 * 3.8). Returning an error aborts the EDHOC session.
	 *
	 * \param[in] user_context      User context.
	 * \param message               Which message is being processed (EAD_1..EAD_4).
	 * \param[in] ead_token         Array of the received EAD items.
	 * \param ead_token_size        Number of received items in \p ead_token.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*process)(void *user_context, enum edhoc_message message,
		       const struct edhoc_ead_token *ead_token,
		       size_t ead_token_size);
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_EAD_H */
