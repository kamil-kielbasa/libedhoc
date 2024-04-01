/**
 * \file    edhoc.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC context and profile.
 * \version 0.1
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "edhoc.h"
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

int edhoc_set_conn_id(struct edhoc_context *ctx, const int32_t *cid,
		      size_t cid_len)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (0 == cid_len || ARRAY_SIZE(ctx->cid) < cid_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	ctx->cid_len = cid_len;
	memcpy(ctx->cid, cid, sizeof(*cid) * cid_len);

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

int edhoc_bind_ead(struct edhoc_context *ctx,
		   const edhoc_ead_compose ead_compose,
		   const edhoc_ead_process ead_process)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (NULL == ead_compose && NULL == ead_process)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	ctx->ead_compose = ead_compose;
	ctx->ead_process = ead_process;

	return EDHOC_SUCCESS;
}

int edhoc_bind_keys(struct edhoc_context *ctx, const struct edhoc_keys keys)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->keys_cb = keys;

	return EDHOC_SUCCESS;
}

int edhoc_bind_crypto(struct edhoc_context *ctx,
		      const struct edhoc_crypto crypto)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->crypto_cb = crypto;

	return EDHOC_SUCCESS;
}

int edhoc_bind_credentials(struct edhoc_context *ctx,
			   const struct edhoc_credentials creds_cb)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->creds_cb = creds_cb;

	return EDHOC_SUCCESS;
}