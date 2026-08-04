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

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* EDHOC headers: */
#include <edhoc/types.h>
#include <edhoc/values.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-ead EDHOC interface EAD
 * @{
 */

/**
 * \brief A single EAD item: a label and an optional value (RFC 9528: 3.8).
 */
struct edhoc_ead_token {
	/** EAD label. A negative label marks the item as critical: the library
	 *  does not act on that, so \ref edhoc_ead.process must fail the session
	 *  when it does not recognise one (RFC 9528: 3.8). */
	int32_t label;

	/** Optional EAD value. Empty when the item carries a label only.
	 *
	 *  Neither side owns the bytes. On compose they belong to the
	 *  application and must stay valid until the composing call returns;
	 *  on process they point into a library buffer released as soon as the
	 *  callback returns, so anything needed later must be copied out. */
	struct edhoc_buffer value;
};

/**
 * \brief External authorization data interface, bound with \ref edhoc_bind_ead.
 *
 *        Both entries are mandatory. The library never takes ownership of a
 *        buffer and never frees one.
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
	 * \param[in] call_context      Context of this call.
	 * \param[out] ead_token        Array to fill with the EAD items to send.
	 * \param ead_token_size        Capacity of the \p ead_token array in entries.
	 * \param[out] ead_token_count    On success, the number of items written.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*compose)(void *user_context,
		       const struct edhoc_call_context *call_context,
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
	 * \param[in] call_context      Context of this call.
	 * \param[in] ead_token         Array of the received EAD items.
	 * \param ead_token_size        Number of received items in \p ead_token.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*process)(void *user_context,
		       const struct edhoc_call_context *call_context,
		       const struct edhoc_ead_token *ead_token,
		       size_t ead_token_size);
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_EAD_H */
