/**
 * \file    edhoc_key_schedule_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC key schedule implementation.
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
#include <edhoc/cipher_suite.h>
#include <edhoc/crypto.h>

/* EDHOC internal headers: */
#include "edhoc_key_schedule_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/**
 * \brief Everything that separates the PRK step of message 2 from that of
 *        message 3.
 */
struct schedule_params {
	/** Handle the step starts from. */
	enum edhoc_key_slot_id prk_source;
	/** Handle the step publishes. */
	enum edhoc_key_slot_id prk_target;
	/** Handle of the static Diffie-Hellman shared secret. */
	enum edhoc_key_slot_id dh_slot;
	/** EDHOC_KDF label of the salt. */
	int32_t salt_label;
	/** Transcript hash the step must be at. */
	enum edhoc_th_state th_stage;
	/** Role that authenticates in this message. */
	enum edhoc_role authenticating_role;
	/** PRK the step must start at. */
	enum edhoc_prk_state prk_source_state;
	/** PRK the step ends at. */
	enum edhoc_prk_state prk_target_state;
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Select the key schedule parameters of the message being handled.
 *
 * \param[in] ctx               EDHOC context.
 * \param[out] params           On success, the selected parameters.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_schedule_params(const struct edhoc_context *ctx,
				struct schedule_params *params);

/**
 * \brief Derive the salt of the current PRK step.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] params            Key schedule parameters.
 * \param[out] salt             Buffer for the salt.
 * \param salt_len              Size of the \p salt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_salt(const struct edhoc_context *ctx,
		     const struct schedule_params *params, uint8_t *salt,
		     size_t salt_len);

/**
 * \brief Agree on the static Diffie-Hellman shared secret of the current
 *        message.
 *
 *        The secret always pairs the authenticating party's static key with
 *        the other party's ephemeral key, so which of the two the local side
 *        holds decides the arguments.
 *
 * \param[in,out] ctx           EDHOC context.
 * \param[in] params            Key schedule parameters.
 * \param[in] private_key_id    Handle of the local authentication key.
 * \param[in] peer_public_key   Peer authentication public key.
 * \param peer_public_key_length Size of \p peer_public_key in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_static_dh_secret(struct edhoc_context *ctx,
				 const struct schedule_params *params,
				 const void *private_key_id,
				 const uint8_t *peer_public_key,
				 size_t peer_public_key_length);

/* Static function definitions --------------------------------------------- */

STATIC int comp_schedule_params(const struct edhoc_context *ctx,
				struct schedule_params *params)
{
	switch (ctx->state.message) {
	case EDHOC_MESSAGE_2:
		*params = (struct schedule_params){
			.prk_source = EDHOC_KEY_SLOT_PRK_2E,
			.prk_target = EDHOC_KEY_SLOT_PRK_3E2M,
			.dh_slot = EDHOC_KEY_SLOT_G_RX,
			.salt_label = EDHOC_KDF_LABEL_SALT_3E2M,
			.th_stage = EDHOC_TH_STATE_2,
			.authenticating_role = EDHOC_ROLE_RESPONDER,
			.prk_source_state = EDHOC_PRK_STATE_2E,
			.prk_target_state = EDHOC_PRK_STATE_3E2M,
		};
		return EDHOC_SUCCESS;

	case EDHOC_MESSAGE_3:
		*params = (struct schedule_params){
			.prk_source = EDHOC_KEY_SLOT_PRK_3E2M,
			.prk_target = EDHOC_KEY_SLOT_PRK_4E3M,
			.dh_slot = EDHOC_KEY_SLOT_G_IY,
			.salt_label = EDHOC_KDF_LABEL_SALT_4E3M,
			.th_stage = EDHOC_TH_STATE_3,
			.authenticating_role = EDHOC_ROLE_INITIATOR,
			.prk_source_state = EDHOC_PRK_STATE_3E2M,
			.prk_target_state = EDHOC_PRK_STATE_4E3M,
		};
		return EDHOC_SUCCESS;

	case EDHOC_MESSAGE_1:
	case EDHOC_MESSAGE_4:
	default:
		return EDHOC_ERROR_BAD_STATE;
	}
}

STATIC int comp_salt(const struct edhoc_context *ctx,
		     const struct schedule_params *params, uint8_t *salt,
		     size_t salt_len)
{
	if (params->th_stage != ctx->state.th.stage ||
	    params->prk_source_state != ctx->state.prk_state) {
		return EDHOC_ERROR_BAD_STATE;
	}

	return edhoc_kdf_expand_raw(ctx,
				    edhoc_key_slot_id(ctx, params->prk_source),
				    params->salt_label, ctx->state.th.value,
				    ctx->state.th.length, salt, salt_len);
}

STATIC int comp_static_dh_secret(struct edhoc_context *ctx,
				 const struct schedule_params *params,
				 const void *private_key_id,
				 const uint8_t *peer_public_key,
				 size_t peer_public_key_length)
{
	/* The party that authenticates in this message contributes its static
	 * key, the other one its ephemeral key. */
	const bool local_authenticates =
		(params->authenticating_role == ctx->state.role);

	void *dh_key_id = edhoc_key_slot_id_mut(ctx, params->dh_slot);
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (local_authenticates) {
		if (NULL == private_key_id) {
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		ret = edhoc_crypto(ctx)->key_agreement(
			ctx->user_context, private_key_id,
			ctx->ephemeral.peer.value, ctx->ephemeral.peer.length,
			dh_key_id);
	} else {
		if (NULL == peer_public_key || 0 == peer_public_key_length) {
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		ret = edhoc_crypto(ctx)->key_agreement(
			ctx->user_context,
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
			peer_public_key, peer_public_key_length, dh_key_id);
	}

	if (EDHOC_SUCCESS != ret) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, params->dh_slot);

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_key_schedule_auth_kind(const struct edhoc_context *ctx, enum edhoc_auth_kind *kind)
{
	if (NULL == ctx || NULL == kind) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	switch (ctx->state.message) {
	case EDHOC_MESSAGE_2:
		switch (ctx->negotiation.selected_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			*kind = EDHOC_AUTH_SIGNATURE;
			return EDHOC_SUCCESS;
		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3:
			*kind = EDHOC_AUTH_STATIC_DH;
			return EDHOC_SUCCESS;
		default:
			EDHOC_LOG_ERR("Invalid method: %d",
				      ctx->negotiation.selected_method);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

	case EDHOC_MESSAGE_3:
		switch (ctx->negotiation.selected_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			*kind = EDHOC_AUTH_SIGNATURE;
			return EDHOC_SUCCESS;
		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
			*kind = EDHOC_AUTH_STATIC_DH;
			return EDHOC_SUCCESS;
		default:
			EDHOC_LOG_ERR("Invalid method: %d",
				      ctx->negotiation.selected_method);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

	case EDHOC_MESSAGE_1:
	case EDHOC_MESSAGE_4:
	default:
		EDHOC_LOG_ERR("Invalid message: %d", ctx->state.message);
		return EDHOC_ERROR_BAD_STATE;
	}
}

int edhoc_key_schedule_encapsulate(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* KEM encapsulate to the peer's encapsulation key G_X: the backend
	 * produces the KEM ciphertext G_Y, stores the shared secret G_XY as a
	 * handle and retains its ephemeral private key for the later static-DH
	 * G_IY agreement in message 3. For classical NIKE-as-KEM suites this
	 * wraps an ephemeral key generation plus a Diffie-Hellman agreement. */
	ctx->ephemeral.own.length = 0;
	const int ret = edhoc_crypto(ctx)->encapsulate(
		ctx->user_context, ctx->ephemeral.peer.value,
		ctx->ephemeral.peer.length,
		edhoc_key_slot_id_mut(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
		edhoc_key_slot_id_mut(ctx, EDHOC_KEY_SLOT_SHARED_SECRET),
		ctx->ephemeral.own.value, sizeof(ctx->ephemeral.own.value),
		&ctx->ephemeral.own.length);

	if (EDHOC_SUCCESS != ret ||
	    csuite->kem_ciphertext_length != ctx->ephemeral.own.length) {
		EDHOC_LOG_ERR("Encapsulate: %d, %zu, %zu", ret,
			      csuite->kem_ciphertext_length,
			      ctx->ephemeral.own.length);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_EPHEMERAL);
	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_SHARED_SECRET);

	return EDHOC_SUCCESS;
}

int edhoc_key_schedule_decapsulate(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* KEM decapsulate the peer's ciphertext G_Y with the ephemeral private
	 * key handle from message 1; the shared secret G_XY is stored as a
	 * handle. */
	const int ret = edhoc_crypto(ctx)->decapsulate(
		ctx->user_context,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
		ctx->ephemeral.peer.value, ctx->ephemeral.peer.length,
		edhoc_key_slot_id_mut(ctx, EDHOC_KEY_SLOT_SHARED_SECRET));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decapsulate: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_SHARED_SECRET);

	return EDHOC_SUCCESS;
}

int edhoc_key_schedule_prk_initial(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_INVALID != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Invalid state for PRK_2e: %d, %d",
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* EDHOC_Extract(salt = TH_2, IKM = G_XY) -> PRK_2e. PRK_2e has its own
	 * dedicated handle because it must outlive PRK_3e2m for KEYSTREAM_2. */
	const int ret = edhoc_kdf_extract(
		ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_SHARED_SECRET),
		ctx->state.th.value, ctx->state.th.length,
		EDHOC_KEY_SLOT_PRK_2E);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Extract PRK_2e: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->state.prk_state = EDHOC_PRK_STATE_2E;

	return EDHOC_SUCCESS;
}

int edhoc_key_schedule_prk_advance(struct edhoc_context *ctx,
				   const void *private_key_id,
				   const uint8_t *peer_public_key,
				   size_t peer_public_key_length)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_is_initiator(ctx) && !edhoc_is_responder(ctx)) {
		EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	struct schedule_params params = { 0 };
	int ret = comp_schedule_params(ctx, &params);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Invalid message for PRK: %d",
			      ctx->state.message);
		return ret;
	}

	if (params.prk_source_state != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad PRK state: %d, %d", ctx->state.prk_state,
			      params.prk_source_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	enum edhoc_auth_kind kind = EDHOC_AUTH_SIGNATURE;
	ret = edhoc_key_schedule_auth_kind(ctx, &kind);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	switch (kind) {
	case EDHOC_AUTH_SIGNATURE:
		/* The key is unchanged, so hand its slot over instead of
		 * deriving again; a single handle then owns it into the next
		 * message. */
		edhoc_key_slot_move(ctx, params.prk_target, params.prk_source);
		ctx->state.prk_state = params.prk_target_state;
		return EDHOC_SUCCESS;

	case EDHOC_AUTH_STATIC_DH: {
		const size_t hash_len =
			edhoc_selected_cipher_suite(ctx)->hash_length;

		EDHOC_MEM_ALLOC(uint8_t, salt, hash_len);
		if (NULL == salt) {
			EDHOC_LOG_ERR("Memory allocation failed");
			return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
		}

		ret = comp_salt(ctx, &params, salt, EDHOC_MEM_ALLOC_SIZE(salt));

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute salt: %d", ret);
			EDHOC_MEM_FREE(salt);
			return ret;
		}

		EDHOC_LOG_HEXDUMP_DBG(salt, EDHOC_MEM_ALLOC_SIZE(salt),
				      "PRK salt");

		ret = comp_static_dh_secret(ctx, &params, private_key_id,
					    peer_public_key,
					    peer_public_key_length);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Static DH shared secret: %d", ret);
			EDHOC_MEM_FREE(salt);
			return ret;
		}

		ret = edhoc_kdf_extract(
			ctx, edhoc_key_slot_id(ctx, params.dh_slot), salt,
			EDHOC_MEM_ALLOC_SIZE(salt), params.prk_target);

		edhoc_zeroize(ctx, salt, EDHOC_MEM_ALLOC_SIZE(salt));
		EDHOC_MEM_FREE(salt);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Extract PRK: %d", ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		ctx->state.prk_state = params.prk_target_state;

		return EDHOC_SUCCESS;
	}

	default:
		EDHOC_LOG_ERR("Invalid authentication kind: %d", kind);
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}
