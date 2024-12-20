/**
 * \file    edhoc.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC context.
 * \version 0.6
 * \date    2024-08-05
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

int edhoc_set_methods(struct edhoc_context *ctx,
		      const enum edhoc_method *method, size_t method_len)
{
	if (NULL == ctx || NULL == method || 0 == method_len ||
	    EDHOC_METHOD_MAX < method_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	ctx->method_len = method_len;
	memcpy(ctx->method, method, sizeof(*method) * method_len);

	return EDHOC_SUCCESS;
}

int edhoc_set_cipher_suites(struct edhoc_context *ctx,
			    const struct edhoc_cipher_suite *csuite,
			    size_t csuite_len)
{
	if (NULL == ctx || NULL == csuite || 0 == csuite_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (ARRAY_SIZE(ctx->csuite) < csuite_len)
		return EDHOC_ERROR_BAD_STATE;

	ctx->csuite_len = csuite_len;
	memcpy(ctx->csuite, csuite, sizeof(*csuite) * csuite_len);

	return EDHOC_SUCCESS;
}

int edhoc_set_connection_id(struct edhoc_context *ctx,
			    const struct edhoc_connection_id *cid)
{
	if (NULL == ctx || NULL == cid)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	switch (cid->encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		if (ONE_BYTE_CBOR_INT_MIN_VALUE > cid->int_value ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE < cid->int_value)
			return EDHOC_ERROR_BAD_STATE;
		break;

	case EDHOC_CID_TYPE_BYTE_STRING:
		if (0 == cid->bstr_length)
			return EDHOC_ERROR_BAD_STATE;

		if (CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID < cid->bstr_length)
			return EDHOC_ERROR_BAD_STATE;
		break;

	default:
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->cid = *cid;

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

int edhoc_bind_ead(struct edhoc_context *ctx, const struct edhoc_ead *ead)
{
	if (NULL == ctx || NULL == ead)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (NULL == ead->compose && NULL == ead->process)
		return EDHOC_ERROR_BAD_STATE;

	ctx->ead = *ead;

	return EDHOC_SUCCESS;
}

int edhoc_bind_keys(struct edhoc_context *ctx, const struct edhoc_keys *keys)
{
	if (NULL == ctx || NULL == keys)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (NULL == keys->import_key || NULL == keys->destroy_key)
		return EDHOC_ERROR_BAD_STATE;

	ctx->keys = *keys;

	return EDHOC_SUCCESS;
}

int edhoc_bind_crypto(struct edhoc_context *ctx,
		      const struct edhoc_crypto *crypto)
{
	if (NULL == ctx || NULL == crypto)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (NULL == crypto->make_key_pair || NULL == crypto->key_agreement ||
	    NULL == crypto->signature || NULL == crypto->verify ||
	    NULL == crypto->extract || NULL == crypto->expand ||
	    NULL == crypto->encrypt || NULL == crypto->decrypt ||
	    NULL == crypto->hash)
		return EDHOC_ERROR_BAD_STATE;

	ctx->crypto = *crypto;

	return EDHOC_SUCCESS;
}

int edhoc_bind_credentials(struct edhoc_context *ctx,
			   const struct edhoc_credentials *cred)
{
	if (NULL == ctx || NULL == cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (NULL == cred->fetch || NULL == cred->verify)
		return EDHOC_ERROR_BAD_STATE;

	ctx->cred = *cred;

	return EDHOC_SUCCESS;
}

int edhoc_error_get_code(const struct edhoc_context *ctx,
			 enum edhoc_error_code *code)
{
	if (NULL == ctx || NULL == code)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	*code = ctx->error_code;
	return EDHOC_SUCCESS;
}

int edhoc_error_get_cipher_suites(const struct edhoc_context *ctx,
				  int32_t *csuites, size_t csuites_size,
				  size_t *csuites_len, int32_t *peer_csuites,
				  size_t peer_csuites_size,
				  size_t *peer_csuites_len)
{
	if (NULL == ctx || NULL == csuites || 0 == csuites_size ||
	    NULL == csuites_len || NULL == peer_csuites ||
	    0 == peer_csuites_size || NULL == peer_csuites_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (!ctx->is_init)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE != ctx->error_code)
		return EDHOC_ERROR_BAD_STATE;

	if (csuites_size < ctx->csuite_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	*csuites_len = ctx->csuite_len;

	for (size_t i = 0; i < ctx->csuite_len; ++i)
		csuites[i] = ctx->csuite[i].value;

	if (peer_csuites_size < ctx->peer_csuite_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	*peer_csuites_len = ctx->peer_csuite_len;

	for (size_t i = 0; i < ctx->peer_csuite_len; ++i)
		peer_csuites[i] = ctx->peer_csuite[i].value;

	return EDHOC_SUCCESS;
}
