/**
 * \file    handshake_ead.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the generic handshake-driver EAD callbacks.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Handshake driver headers: */
#include "handshake_ead.h"
#include "handshake_driver.h"

/* EDHOC header: */
#include <edhoc/edhoc.h>

/* Standard library headers: */
#include <string.h>

/* Static function declarations -------------------------------------------- */

/**
 * \brief Map an EDHOC message to its zero-based index in \ref hs_ead.message.
 */
static int hs_ead_index(enum edhoc_message message, size_t *index);

/* Static function definitions --------------------------------------------- */

static int hs_ead_index(enum edhoc_message message, size_t *index)
{
	switch (message) {
	case EDHOC_MESSAGE_1:
		*index = 0;
		return EDHOC_SUCCESS;
	case EDHOC_MESSAGE_2:
		*index = 1;
		return EDHOC_SUCCESS;
	case EDHOC_MESSAGE_3:
		*index = 2;
		return EDHOC_SUCCESS;
	case EDHOC_MESSAGE_4:
		*index = 3;
		return EDHOC_SUCCESS;
	default:
		return EDHOC_ERROR_GENERIC_ERROR;
	}
}

/* Module interface function definitions ----------------------------------- */

int hs_ead_compose(void *user_context,
		   const struct edhoc_call_context *call_context,
		   struct edhoc_ead_token *ead_token, size_t ead_token_size,
		   size_t *ead_token_count)
{
	const struct handshake_endpoint *endpoint = user_context;

	if (NULL == endpoint || NULL == endpoint->ead || NULL == call_context ||
	    NULL == ead_token || NULL == ead_token_count ||
	    0 == ead_token_size) {
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	size_t msg_index = 0;

	if (EDHOC_SUCCESS != hs_ead_index(call_context->message, &msg_index)) {
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	if (endpoint->role != call_context->role) {
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	const struct hs_ead_message *expected =
		&endpoint->ead->message[msg_index];

	if (expected->token_count > ead_token_size) {
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	for (size_t i = 0; i < expected->token_count; ++i) {
		ead_token[i] = *expected->token[i];
	}

	*ead_token_count = expected->token_count;
	return EDHOC_SUCCESS;
}

int hs_ead_process(void *user_context,
		   const struct edhoc_call_context *call_context,
		   const struct edhoc_ead_token *ead_token,
		   size_t ead_token_size)
{
	const struct handshake_endpoint *endpoint = user_context;

	if (NULL == endpoint || NULL == endpoint->ead || NULL == call_context ||
	    (0 != ead_token_size && NULL == ead_token)) {
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	size_t msg_index = 0;

	if (EDHOC_SUCCESS != hs_ead_index(call_context->message, &msg_index)) {
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	if (endpoint->role != call_context->role) {
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	const struct hs_ead_message *expected =
		&endpoint->ead->message[msg_index];

	/* Reject the session unless the received tokens match the table; the
	 * library aborts and the driver sees the failing message API. */
	if (expected->token_count != ead_token_size) {
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	for (size_t i = 0; i < expected->token_count; ++i) {
		const struct edhoc_ead_token *want = expected->token[i];

		if (want->label != ead_token[i].label) {
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}

		if (want->value.length != ead_token[i].value.length) {
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}

		if (0 != memcmp(want->value.value, ead_token[i].value.value,
				want->value.length)) {
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}
	}

	return EDHOC_SUCCESS;
}
