/**
 * \file    edhoc_ead_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC external authorization data implementation.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC public headers: */
#include <edhoc/types.h>
#include <edhoc/values.h>
#include <edhoc/ead.h>

/* EDHOC internal headers: */
#include "edhoc_ead_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* CBOR headers: */
#include <backend_cbor_types.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Number of the message currently being handled, as it appears in the
 *        EAD_x name.
 *
 * \param[in] ctx               EDHOC context.
 *
 * \return Message number, one to four.
 */
STATIC int comp_message_number(const struct edhoc_context *ctx);

/**
 * \brief Validate the items the application produced in \ref edhoc_ead.compose,
 *        then hex-dump the accepted ones at debug level.
 *
 *        Both the count and the item buffers go straight to the CBOR encoder,
 *        which can neither tell a missing buffer from an empty one nor notice
 *        that a callback reported more items than it was given room for.
 *
 * \param[in] tokens            Items to send.
 * \param nr_of_tokens          Number of entries in \p tokens.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int validate_composed(const struct edhoc_ead_token *tokens,
			     size_t nr_of_tokens);

/* Static function definitions --------------------------------------------- */

STATIC int comp_message_number(const struct edhoc_context *ctx)
{
	return (int)ctx->state.message + 1;
}

STATIC int validate_composed(const struct edhoc_ead_token *tokens,
			     size_t nr_of_tokens)
{
	if (EDHOC_EAD_CAPACITY < nr_of_tokens) {
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	for (size_t i = 0; i < nr_of_tokens; ++i) {
		if (NULL == tokens[i].value.value &&
		    0 != tokens[i].value.length) {
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
		}
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

bool edhoc_ead_is_present(const struct edhoc_context *ctx)
{
	return 0 != ctx->ead.count;
}

bool edhoc_ead_may_compose(const struct edhoc_context *ctx)
{
	return NULL != ctx->interfaces.ead.compose && 0 != EDHOC_EAD_CAPACITY;
}

bool edhoc_ead_may_process(const struct edhoc_context *ctx)
{
	return NULL != ctx->interfaces.ead.process && edhoc_ead_is_present(ctx);
}

void edhoc_ead_reset(struct edhoc_context *ctx)
{
	edhoc_zeroize(ctx, &ctx->ead, sizeof(ctx->ead));
}

int edhoc_ead_compose(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_ead_may_compose(ctx)) {
		EDHOC_LOG_DBG("EAD_%d compose skipped: no callback or no room",
			      comp_message_number(ctx));
		return EDHOC_SUCCESS;
	}

	const struct edhoc_call_context call_context = edhoc_call_context(ctx);

	int ret = ctx->interfaces.ead.compose(ctx->user_context, &call_context,
					      ctx->ead.token,
					      EDHOC_EAD_CAPACITY,
					      &ctx->ead.count);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("EAD_%d compose: %d", comp_message_number(ctx),
			      ret);
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	ret = validate_composed(ctx->ead.token, ctx->ead.count);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("EAD_%d compose validation: %d, %zu",
			      comp_message_number(ctx), ret, ctx->ead.count);
		return ret;
	}

	for (size_t i = 0; i < ctx->ead.count; ++i) {
		EDHOC_LOG_DBG("EAD_%d compose token label: %d",
			      comp_message_number(ctx),
			      ctx->ead.token[i].label);

		if (0 != ctx->ead.token[i].value.length) {
			EDHOC_LOG_HEXDUMP_DBG(ctx->ead.token[i].value.value,
					      ctx->ead.token[i].value.length,
					      "EAD compose token value");
		}
	}

	return EDHOC_SUCCESS;
}

int edhoc_ead_process(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_ead_may_process(ctx)) {
		EDHOC_LOG_DBG("EAD_%d process skipped: no callback or no token",
			      comp_message_number(ctx));
		return EDHOC_SUCCESS;
	}

	for (size_t i = 0; i < ctx->ead.count; ++i) {
		EDHOC_LOG_DBG("EAD_%d process token label: %d",
			      comp_message_number(ctx),
			      ctx->ead.token[i].label);

		if (0 != ctx->ead.token[i].value.length) {
			EDHOC_LOG_HEXDUMP_DBG(ctx->ead.token[i].value.value,
					      ctx->ead.token[i].value.length,
					      "EAD process token value");
		}
	}

	const struct edhoc_call_context call_context = edhoc_call_context(ctx);

	const int ret =
		ctx->interfaces.ead.process(ctx->user_context, &call_context,
					    ctx->ead.token, ctx->ead.count);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("EAD_%d process: %d", comp_message_number(ctx),
			      ret);
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_ead_encoded_length(const struct edhoc_context *ctx, size_t *length)
{
	if (NULL == ctx || NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	size_t len = 0;

	for (size_t i = 0; i < ctx->ead.count; ++i) {
		len += edhoc_cbor_int_head_length(ctx->ead.token[i].label);
		len += ctx->ead.token[i].value.length;
		len += edhoc_cbor_bstr_head_length(
			ctx->ead.token[i].value.length);
	}

	*length = len;

	return EDHOC_SUCCESS;
}

int edhoc_ead_tokens_encode(const struct edhoc_context *ctx, struct ead *tokens)
{
	if (NULL == ctx || NULL == tokens) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (ctx->ead.count > ARRAY_SIZE(tokens->ead)) {
		EDHOC_LOG_ERR("EAD buffer too small: %zu, %zu", ctx->ead.count,
			      ARRAY_SIZE(tokens->ead));
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	for (size_t i = 0; i < ctx->ead.count; ++i) {
		tokens->ead[i].ead_x_ead_label = ctx->ead.token[i].label;
		tokens->ead[i].ead_x_ead_value_present =
			(NULL != ctx->ead.token[i].value.value);
		tokens->ead[i].ead_x_ead_value.value =
			ctx->ead.token[i].value.value;
		tokens->ead[i].ead_x_ead_value.len =
			ctx->ead.token[i].value.length;
	}

	tokens->ead_count = ctx->ead.count;

	return EDHOC_SUCCESS;
}

int edhoc_ead_tokens_decode(struct edhoc_context *ctx, const struct ead *tokens)
{
	if (NULL == ctx || NULL == tokens) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (tokens->ead_count > EDHOC_EAD_CAPACITY) {
		EDHOC_LOG_ERR("EAD buffer too small: %zu, %d",
			      tokens->ead_count, EDHOC_EAD_CAPACITY);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	ctx->ead.count = tokens->ead_count;

	for (size_t i = 0; i < tokens->ead_count; ++i) {
		ctx->ead.token[i].label = tokens->ead[i].ead_x_ead_label;

		/* zcbor keeps the length read from a bstr header even when the
		 * value itself did not fit in the payload, so only the presence
		 * flag may be trusted here. */
		if (tokens->ead[i].ead_x_ead_value_present) {
			ctx->ead.token[i].value.value =
				tokens->ead[i].ead_x_ead_value.value;
			ctx->ead.token[i].value.length =
				tokens->ead[i].ead_x_ead_value.len;
		} else {
			ctx->ead.token[i].value.value = NULL;
			ctx->ead.token[i].value.length = 0;
		}
	}

	return EDHOC_SUCCESS;
}
