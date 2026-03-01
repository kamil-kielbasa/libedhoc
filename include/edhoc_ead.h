/**
 * \file    edhoc_ead.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC External Authorization Data (EAD) interface.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
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
 * \brief Helper type for recognition of EDHOC message in EAD callback.
 */
enum edhoc_message {
	/** EDHOC message 1. */
	EDHOC_MSG_1,
	/** EDHOC message 2. */
	EDHOC_MSG_2,
	/** EDHOC message 3. */
	EDHOC_MSG_3,
	/** EDHOC message 4. */
	EDHOC_MSG_4,
};

/**
 * \brief RFC 9528: 3.8. External Authorization Data (EAD).
 */
struct edhoc_ead_token {
	/** EAD label value. */
	int32_t label;

	/** EAD buffer. */
	const uint8_t *value;
	/** Size of the \p value buffer in bytes. */
	size_t value_len;
};

/** 
 * \brief Compose external authorization data (EAD) tokens.
 *
 * Called by the library during message composition to let the application
 * attach EAD items to the outgoing EDHOC message.
 *
 * \param[in] user_context      User context.
 * \param message               EDHOC message number (EAD_1, EAD_2, EAD_3, or EAD_4).
 * \param[in,out] ead_token     Array where the generated EAD tokens are written.
 * \param ead_token_size        Maximum number of entries in the \p ead_token array.
 * \param[out] ead_token_len    On success, the number of EAD tokens written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
typedef int (*edhoc_ead_compose_t)(void *user_context,
				   enum edhoc_message message,
				   struct edhoc_ead_token *ead_token,
				   size_t ead_token_size,
				   size_t *ead_token_len);

/** 
 * \brief Process received external authorization data (EAD) tokens.
 *
 * Called by the library during message processing to deliver received
 * EAD items to the application for validation.
 *
 * \param[in] user_context      User context.
 * \param message               EDHOC message number (EAD_1, EAD_2, EAD_3, or EAD_4).
 * \param[in] ead_token         Array containing the received EAD tokens.
 * \param ead_token_size        Number of entries in the \p ead_token array.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
typedef int (*edhoc_ead_process_t)(void *user_context,
				   enum edhoc_message message,
				   const struct edhoc_ead_token *ead_token,
				   size_t ead_token_size);

/**
 * \brief Bind structure for EAD operations.
 */
struct edhoc_ead {
	/** External authorization data compose callback. */
	edhoc_ead_compose_t compose;
	/** External authorization data process callback. */
	edhoc_ead_process_t process;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_EAD_H */
