/**
 * \file    edhoc.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC context.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* EDHOC public headers: */
#include <edhoc/edhoc.h>
#include <edhoc/types.h>
#include <edhoc/values.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/credentials.h>
#include <edhoc/crypto.h>
#include <edhoc/ead.h>
#include <edhoc/platform.h>

/* EDHOC internal headers: */
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_classic_internal.h"
#include "edhoc_psk_internal.h"
#include "edhoc_error_internal.h"
#include "edhoc_exporter_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
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
	 * Latch the callback first - the wipe also clears ctx->interfaces.platform. */
	void (*const zeroize)(void *buffer, size_t length) =
		ctx->interfaces.platform.zeroize;

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
	    CONFIG_LIBEDHOC_MAX_NR_OF_METHODS < method_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	for (size_t i = 0; i < method_len; ++i) {
		switch (method[i]) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
		case EDHOC_METHOD_4:
			break;
		default:
			EDHOC_LOG_ERR("Invalid method: %d", method[i]);
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->negotiation.method.count = method_len;
	memcpy(ctx->negotiation.method.entry, method,
	       sizeof(*method) * method_len);
	ctx->negotiation.methods_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_set_cipher_suites(struct edhoc_context *ctx,
			    const struct edhoc_cipher_suite *csuite,
			    size_t csuite_len)
{
	if (NULL == ctx || NULL == csuite || 0 == csuite_len ||
	    CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES < csuite_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->negotiation.cipher_suite.count = csuite_len;
	memcpy(ctx->negotiation.cipher_suite.entry, csuite,
	       sizeof(*csuite) * csuite_len);
	ctx->negotiation.cipher_suites_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_set_connection_id(struct edhoc_context *ctx,
			    const struct edhoc_buffer *cid)
{
	if (NULL == ctx || NULL == cid ||
	    (NULL == cid->value && 0 != cid->length)) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	const int ret = edhoc_connection_id_from_bstr(
		cid->value, cid->length, &ctx->negotiation.connection_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Connection ID conversion: %d", ret);
		return ret;
	}

	ctx->negotiation.connection_id_present = true;

	return EDHOC_SUCCESS;
}

int edhoc_set_user_context(struct edhoc_context *ctx, void *user_ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->user_context = user_ctx;

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

	if (NULL == ead->compose || NULL == ead->process) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	ctx->interfaces.ead = *ead;
	ctx->interfaces.ead_present = true;

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
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	ctx->interfaces.crypto = *crypto;
	ctx->interfaces.crypto_present = true;

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

	if (NULL == cred->select_local || NULL == cred->authenticate_peer) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	ctx->interfaces.cred = *cred;
	ctx->interfaces.credentials_present = true;

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
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	ctx->interfaces.platform = *platform;
	ctx->interfaces.platform_present = true;

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

	if (csuites_size < ctx->negotiation.cipher_suite.count) {
		EDHOC_LOG_ERR("Cipher suites length too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*csuites_len = ctx->negotiation.cipher_suite.count;

	for (size_t i = 0; i < ctx->negotiation.cipher_suite.count; ++i)
		csuites[i] = ctx->negotiation.cipher_suite.entry[i].value;

	if (peer_csuites_size < ctx->negotiation.peer_cipher_suite.count) {
		EDHOC_LOG_ERR("Peer cipher suites length too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*peer_csuites_len = ctx->negotiation.peer_cipher_suite.count;

	for (size_t i = 0; i < ctx->negotiation.peer_cipher_suite.count; ++i)
		peer_csuites[i] =
			ctx->negotiation.peer_cipher_suite.entry[i].value;

	return EDHOC_SUCCESS;
}

int edhoc_message_1_compose(struct edhoc_context *ctx, uint8_t *msg_1,
			    size_t msg_1_size, size_t *msg_1_len)
{
	return edhoc_classic_message_1_compose(ctx, msg_1, msg_1_size,
					       msg_1_len);
}

int edhoc_message_1_process(struct edhoc_context *ctx, const uint8_t *msg_1,
			    size_t msg_1_len)
{
	return edhoc_classic_message_1_process(ctx, msg_1, msg_1_len);
}

int edhoc_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
			    size_t msg_2_size, size_t *msg_2_len)
{
	if (edhoc_psk_is_selected(ctx)) {
		return edhoc_psk_message_2_compose(ctx, msg_2, msg_2_size,
						   msg_2_len);
	}

	return edhoc_classic_message_2_compose(ctx, msg_2, msg_2_size,
					       msg_2_len);
}

int edhoc_message_2_process(struct edhoc_context *ctx, const uint8_t *msg_2,
			    size_t msg_2_len)
{
	if (edhoc_psk_is_selected(ctx)) {
		return edhoc_psk_message_2_process(ctx, msg_2, msg_2_len);
	}

	return edhoc_classic_message_2_process(ctx, msg_2, msg_2_len);
}

int edhoc_message_3_compose(struct edhoc_context *ctx, uint8_t *msg_3,
			    size_t msg_3_size, size_t *msg_3_len)
{
	if (edhoc_psk_is_selected(ctx)) {
		return edhoc_psk_message_3_compose(ctx, msg_3, msg_3_size,
						   msg_3_len);
	}

	return edhoc_classic_message_3_compose(ctx, msg_3, msg_3_size,
					       msg_3_len);
}

int edhoc_message_3_process(struct edhoc_context *ctx, const uint8_t *msg_3,
			    size_t msg_3_len)
{
	if (edhoc_psk_is_selected(ctx)) {
		return edhoc_psk_message_3_process(ctx, msg_3, msg_3_len);
	}

	return edhoc_classic_message_3_process(ctx, msg_3, msg_3_len);
}

int edhoc_message_4_compose(struct edhoc_context *ctx, uint8_t *msg_4,
			    size_t msg_4_size, size_t *msg_4_len)
{
	return edhoc_classic_message_4_compose(ctx, msg_4, msg_4_size,
					       msg_4_len);
}

int edhoc_message_4_process(struct edhoc_context *ctx, const uint8_t *msg_4,
			    size_t msg_4_len)
{
	return edhoc_classic_message_4_process(ctx, msg_4, msg_4_len);
}

int edhoc_message_error_compose(struct edhoc_context *ctx, uint8_t *msg_err,
				size_t msg_err_size, size_t *msg_err_len,
				enum edhoc_error_code code,
				const struct edhoc_error_info *info)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init || EDHOC_SM_COMPLETED <= ctx->state.machine) {
		EDHOC_LOG_ERR("Bad state: %d", ctx->state.machine);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

	const int ret = edhoc_error_encode(msg_err, msg_err_size, msg_err_len,
					   code, info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encode error message: %d", ret);
		return ret;
	}

	ctx->error_code = code;

	return EDHOC_SUCCESS;
}

int edhoc_message_error_process(struct edhoc_context *ctx,
				const uint8_t *msg_err, size_t msg_err_len,
				enum edhoc_error_code *code,
				struct edhoc_error_info *info)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init || EDHOC_SM_COMPLETED <= ctx->state.machine) {
		EDHOC_LOG_ERR("Bad state: %d", ctx->state.machine);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

	const int ret = edhoc_error_decode(msg_err, msg_err_len, code, info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decode error message: %d", ret);
		return ret;
	}

	/* SUITES_R becomes the peer suites for edhoc_error_get_cipher_suites. */
	if (EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == *code &&
	    NULL != info && 0 != info->entries_length) {
		if (ARRAY_SIZE(ctx->negotiation.peer_cipher_suite.entry) <
		    info->entries_length) {
			EDHOC_LOG_ERR(
				"Buffer too small for peer cipher suites: %zu, %zu",
				info->entries_length,
				ARRAY_SIZE(ctx->negotiation.peer_cipher_suite
						   .entry));
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		ctx->negotiation.peer_cipher_suite.count = info->entries_length;

		for (size_t i = 0; i < info->entries_length; ++i) {
			ctx->negotiation.peer_cipher_suite.entry[i].value =
				info->cipher_suites[i];
		}
	}

	ctx->error_code = *code;

	return EDHOC_SUCCESS;
}

int edhoc_export(struct edhoc_context *ctx, size_t label,
		 const uint8_t *context, size_t context_len,
		 enum edhoc_key_usage usage, void *key_id)
{
	return edhoc_exporter_export(ctx, label, context, context_len, usage,
				     key_id);
}

int edhoc_export_raw(struct edhoc_context *ctx, size_t label,
		     const uint8_t *context, size_t context_len,
		     uint8_t *secret, size_t secret_len)
{
	return edhoc_exporter_export_raw(ctx, label, context, context_len,
					 secret, secret_len);
}

int edhoc_export_resumption_psk(struct edhoc_context *ctx,
				enum edhoc_key_usage usage, void *key_id)
{
	return edhoc_exporter_export(ctx, EDHOC_EXPORTER_LABEL_RESUMPTION_PSK,
				     NULL, 0, usage, key_id);
}

int edhoc_export_resumption_psk_raw(struct edhoc_context *ctx, uint8_t *psk,
				    size_t psk_len)
{
	return edhoc_exporter_export_raw(ctx,
					 EDHOC_EXPORTER_LABEL_RESUMPTION_PSK,
					 NULL, 0, psk, psk_len);
}

int edhoc_export_resumption_kid_raw(struct edhoc_context *ctx, uint8_t *kid,
				    size_t kid_len)
{
	return edhoc_exporter_export_raw(ctx,
					 EDHOC_EXPORTER_LABEL_RESUMPTION_KID,
					 NULL, 0, kid, kid_len);
}

int edhoc_export_key_update(struct edhoc_context *ctx, const uint8_t *context,
			    size_t context_len)
{
	return edhoc_exporter_key_update(ctx, context, context_len);
}

int edhoc_export_oscore_context(struct edhoc_context *ctx,
				void *master_secret_key_id, uint8_t *salt,
				size_t salt_len, uint8_t *sid, size_t sid_size,
				size_t *sid_len, uint8_t *rid, size_t rid_size,
				size_t *rid_len)
{
	return edhoc_exporter_oscore_context(ctx, master_secret_key_id, salt,
					     salt_len, sid, sid_size, sid_len,
					     rid, rid_size, rid_len);
}

int edhoc_export_oscore_context_raw(struct edhoc_context *ctx, uint8_t *secret,
				    size_t secret_len, uint8_t *salt,
				    size_t salt_len, uint8_t *sid,
				    size_t sid_size, size_t *sid_len,
				    uint8_t *rid, size_t rid_size,
				    size_t *rid_len)
{
	return edhoc_exporter_oscore_context_raw(ctx, secret, secret_len, salt,
						 salt_len, sid, sid_size,
						 sid_len, rid, rid_size,
						 rid_len);
}
