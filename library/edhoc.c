/**
 * \file    edhoc.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC context.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"

/* Standard library headers: */
#include <stddef.h>
#include <string.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

int edhoc_context_init(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*ctx = (struct edhoc_context){
		.is_init = true,
	};

	return EDHOC_SUCCESS;
}

int edhoc_context_deinit(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	memset(ctx, 0, sizeof(*ctx));

	return EDHOC_SUCCESS;
}

int edhoc_set_method(struct edhoc_context *ctx, enum edhoc_method method)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->method = method;

	return EDHOC_SUCCESS;
}

int edhoc_set_cipher_suites(struct edhoc_context *ctx,
			    const struct edhoc_cipher_suite *csuite,
			    size_t csuite_len)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (0 == csuite_len || ARRAY_SIZE(ctx->csuite) < csuite_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	ctx->csuite_len = csuite_len;
	memcpy(ctx->csuite, csuite, sizeof(*csuite) * csuite_len);

	return EDHOC_SUCCESS;
}

int edhoc_set_connection_id(struct edhoc_context *ctx,
			    struct edhoc_connection_id cid)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	switch (cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		if (ONE_BYTE_CBOR_INT_MIN_VALUE > cid.int_value ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE < cid.int_value)
			return EDHOC_ERROR_INVALID_ARGUMENT;
		break;

	case EDHOC_CID_TYPE_BYTE_STRING:
		if (0 == cid.bstr_length)
			return EDHOC_ERROR_INVALID_ARGUMENT;

		if (EDHOC_MAX_CID_LEN < cid.bstr_length)
			return EDHOC_ERROR_INVALID_ARGUMENT;
		break;

	default:
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->cid = cid;

	return EDHOC_SUCCESS;
}

int edhoc_set_user_context(struct edhoc_context *ctx, void *user_ctx)
{
	if (NULL == ctx || NULL == user_ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->user_ctx = user_ctx;

	return EDHOC_SUCCESS;
}

int edhoc_bind_ead(struct edhoc_context *ctx, struct edhoc_ead ead)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (NULL == ead.compose && NULL == ead.process)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	ctx->ead = ead;

	return EDHOC_SUCCESS;
}

int edhoc_bind_keys(struct edhoc_context *ctx, struct edhoc_keys keys)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->keys = keys;

	return EDHOC_SUCCESS;
}

int edhoc_bind_crypto(struct edhoc_context *ctx, struct edhoc_crypto crypto)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->crypto = crypto;

	return EDHOC_SUCCESS;
}

int edhoc_bind_credentials(struct edhoc_context *ctx,
			   struct edhoc_credentials cred)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->cred = cred;

	return EDHOC_SUCCESS;
}
