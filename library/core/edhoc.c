/**
 * \file    edhoc.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC context.
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

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
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	*ctx = (struct edhoc_context){
		.is_init = true,
	};

	return EDHOC_SUCCESS;
}

size_t edhoc_context_size(void)
{
	return sizeof(struct edhoc_context);
}

int edhoc_context_deinit(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	/* Free every live key-store slot: the handles are backend key-store
	 * slots, so wiping the context memory alone would leak them. On the
	 * first destroy failure stop and report it (the wipe is skipped). */
	int ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_COUNT);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release key slots: %d", ret);
		return ret;
	}

	/* End-of-life erasure: use the non-elidable platform hook when a
	 * platform is bound (any secret material only ever exists after
	 * binding); otherwise a plain wipe is sufficient (no secrets yet).
	 * Latch the callback first - the wipe also clears ctx->itf.platform. */
	void (*const zeroize)(void *buffer, size_t length) =
		ctx->itf.platform.zeroize;

	if (NULL != zeroize) {
		zeroize(ctx, sizeof(*ctx));
	} else {
		memset(ctx, 0, sizeof(*ctx));
	}

	return EDHOC_SUCCESS;
}

int edhoc_set_methods(struct edhoc_context *ctx,
		      const enum edhoc_method *method, size_t method_len)
{
	if (NULL == ctx || NULL == method || 0 == method_len ||
	    EDHOC_METHOD_MAX < method_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->method_len = method_len;
	memcpy(ctx->method, method, sizeof(*method) * method_len);
	ctx->methods_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_set_cipher_suites(struct edhoc_context *ctx,
			    const struct edhoc_cipher_suite *csuite,
			    size_t csuite_len)
{
	if (NULL == ctx || NULL == csuite || 0 == csuite_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (ARRAY_SIZE(ctx->csuite) < csuite_len) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->csuite_len = csuite_len;
	memcpy(ctx->csuite, csuite, sizeof(*csuite) * csuite_len);
	ctx->cipher_suites_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_set_connection_id(struct edhoc_context *ctx,
			    const struct edhoc_connection_id *cid)
{
	if (NULL == ctx || NULL == cid) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	switch (cid->encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		if (ONE_BYTE_CBOR_INT_MIN_VALUE > cid->int_value ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE < cid->int_value) {
			EDHOC_LOG_ERR("Bad state");
			return EDHOC_ERROR_BAD_STATE;
		}
		break;

	case EDHOC_CID_TYPE_BYTE_STRING:
		if (0 == cid->bstr_length) {
			EDHOC_LOG_ERR("Bad state");
			return EDHOC_ERROR_BAD_STATE;
		}

		if (CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID < cid->bstr_length) {
			EDHOC_LOG_ERR("Bad state");
			return EDHOC_ERROR_BAD_STATE;
		}
		break;

	default:
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->cid = *cid;
	ctx->connection_id_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_set_user_context(struct edhoc_context *ctx, void *user_ctx)
{
	if (NULL == ctx || NULL == user_ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->user_ctx = user_ctx;

	return EDHOC_SUCCESS;
}

int edhoc_bind_ead(struct edhoc_context *ctx, const struct edhoc_ead *ead)
{
	if (NULL == ctx || NULL == ead) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (NULL == ead->compose && NULL == ead->process) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->itf.ead = *ead;
	ctx->itf.ead_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_bind_crypto(struct edhoc_context *ctx,
		      const struct edhoc_crypto *crypto)
{
	if (NULL == ctx || NULL == crypto) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (NULL == crypto->destroy_key || NULL == crypto->generate_key_pair ||
	    NULL == crypto->encapsulate || NULL == crypto->decapsulate ||
	    NULL == crypto->key_agreement || NULL == crypto->sign ||
	    NULL == crypto->verify || NULL == crypto->extract ||
	    NULL == crypto->expand || NULL == crypto->expand_raw ||
	    NULL == crypto->aead_encrypt || NULL == crypto->aead_decrypt ||
	    NULL == crypto->hash_init || NULL == crypto->hash_update ||
	    NULL == crypto->hash_finish || NULL == crypto->hash_abort) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->itf.crypto = *crypto;
	ctx->itf.crypto_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_bind_credentials(struct edhoc_context *ctx,
			   const struct edhoc_credentials *cred)
{
	if (NULL == ctx || NULL == cred) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (NULL == cred->fetch || NULL == cred->verify) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->itf.cred = *cred;
	ctx->itf.credentials_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_bind_platform(struct edhoc_context *ctx,
			const struct edhoc_platform *platform)
{
	if (NULL == ctx || NULL == platform) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (NULL == platform->zeroize) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->itf.platform = *platform;
	ctx->itf.platform_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_error_get_code(const struct edhoc_context *ctx,
			 enum edhoc_error_code *code)
{
	if (NULL == ctx || NULL == code) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

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
	    0 == peer_csuites_size || NULL == peer_csuites_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE != ctx->error_code) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (csuites_size < ctx->csuite_len) {
		EDHOC_LOG_ERR("Cipher suites length too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*csuites_len = ctx->csuite_len;

	for (size_t i = 0; i < ctx->csuite_len; ++i)
		csuites[i] = ctx->csuite[i].value;

	if (peer_csuites_size < ctx->peer_csuite_len) {
		EDHOC_LOG_ERR("Peer cipher suites length too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*peer_csuites_len = ctx->peer_csuite_len;

	for (size_t i = 0; i < ctx->peer_csuite_len; ++i)
		peer_csuites[i] = ctx->peer_csuite[i].value;

	return EDHOC_SUCCESS;
}
