/**
 * \file    edhoc_message_2.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 2 compose & process.
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
#include <edhoc/edhoc.h>
#include <edhoc/types.h>
#include <edhoc/values.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/credentials.h>

/* EDHOC internal headers: */
#include "edhoc_context_internal.h"
#include "edhoc_values_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_common_internal.h"
#include "edhoc_credentials_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_edhoc_types.h>
#include <backend_cbor_x509_types.h>
#include <backend_cbor_message_2_encode.h>
#include <backend_cbor_message_2_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_info_encode.h>
#include <backend_cbor_plaintext_2_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief KEM encapsulate to the peer's G_X (Responder): produce the KEM
 *        ciphertext G_Y (into \p ctx->ephemeral.own.value) and the ephemeral
 *        shared-secret handle.
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_encapsulate(struct edhoc_context *ctx);

/**
 * \brief KEM decapsulate the peer's G_Y (Initiator): derive the ephemeral
 *        shared-secret handle from the message-1 ephemeral private key.
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_decapsulate(struct edhoc_context *ctx);

/**
 * \brief Compute transcript hash 2 (TH_2).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_th_2(struct edhoc_context *ctx);

/**
 * \brief Compute pseudorandom key (PRK_2e).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_prk_2e(struct edhoc_context *ctx);

/**
 * \brief Compute pseudorandom key (PRK_3e2m).
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] private_key_id    Handle of the local static-DH authentication key
 *                              (Responder only, otherwise NULL).
 * \param[in] peer_public_key   Peer static-DH authentication key (Initiator
 *                              only, otherwise NULL).
 * \param peer_public_key_length Size of the \p peer_public_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_prk_3e2m(struct edhoc_context *ctx, const void *private_key_id,
			 const uint8_t *peer_public_key,
			 size_t peer_public_key_length);

/**
 * \brief Compute required PLAINTEXT_2 length.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] mac_ctx		MAC_2 context.
 * \param sign_len		Size of the signature buffer in bytes.
 * \param[out] plaintext_2_len  On success, length of PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_plaintext_2_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_2_len);

/**
 * \brief Prepare PLAINTEXT_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] mac_ctx		Buffer containing the context_2.
 * \param[in] sign		Buffer containing the signature.
 * \param sign_len		Size of the \p sign buffer in bytes.
 * \param[out] ptxt	        Buffer where the generated plaintext is to be written.
 * \param ptxt_size		Size of the \p ptxt buffer in bytes.
 * \param[out] ptxt_len		On success, the number of bytes that make up the PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);

/**
 * \brief Compute KEYSTREAM_2 from the context PRK_2e handle (or PRK_3e2m for
 *        methods 0/2, into which PRK_2e was moved).
 *
 * \param[in] ctx		EDHOC context.
 * \param[out] keystream	Buffer where the generated keystream is to be written.
 * \param keystream_len		Size of the \p keystream buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_keystream(const struct edhoc_context *ctx, uint8_t *keystream,
			  size_t keystream_len);

/**
 * \brief Compute CIPHERTEXT_2.
 *
 * \param[out] dst		Memory location to XOR to.
 * \param[in] src		Memory location to XOR from.
 * \param count			Number of bytes to XOR.
 */
STATIC void xor_arrays(uint8_t *restrict dst, const uint8_t *restrict src,
		       size_t count);

/**
 * \brief Prepare MESSAGE_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ciphertext	Buffer containing the CIPHERTEXT_2.
 * \param ciphertext_len	Size of the \p ciphertext buffer in bytes.
 * \param[out] msg_2        	Buffer where the generated message 2 is to be written.
 * \param msg_2_size        	Size of the \p msg_2 buffer in bytes.
 * \param[out] msg_2_len	On success, the number of bytes that make up the message 2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ciphertext, size_t ciphertext_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len);

/**
 * \brief Compute from cborised message 2 length of ciphertext 2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message 2.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[out] len		Length of ciphertext 2 in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_ciphertext_2_len(const struct edhoc_context *ctx,
				 const uint8_t *msg_2, size_t msg_2_len,
				 size_t *len);

/**
 * \brief Decode message 2 and save into context and buffer.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message 2.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[in] ctxt_2	        Buffer containing the CIPHERTEXT_2.
 * \param ctxt_2_len	        Size of the \p ctxt_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len);

/**
 * \brief Parsed cborised PLAINTEXT_2 for separate buffers.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_2.
 * \param ptxt_len              Size of the \p plaintext buffer in bytes.
 * \param[out] parsed_ptxt     	Structure where parsed PLAINTEXT_2 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_plaintext_2(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len, struct plaintext *parsed_ptxt);

/**
 * \brief Compute transcript hash 3.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] mac_ctx	        MAC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_2.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);

/**
 * \brief Compute SALT_3e2m.
 *
 * \param[in] ctx               EDHOC context.
 * \param[out] salt             Buffer where the generated salt is to be written.
 * \param salt_len              Size of the \p salt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len);

/**
 * \brief Compute G_RX for PRK_3e2m into its context key slot.
 *
 * \param[in,out] ctx           EDHOC context.
 * \param[in] private_key_id    Handle of the local static-DH authentication key
 *                              (Responder only).
 * \param[in] peer_public_key   Peer static-DH authentication key (Initiator
 *                              only).
 * \param peer_public_key_length Size of the \p peer_public_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_grx(struct edhoc_context *ctx, const void *private_key_id,
		    const uint8_t *peer_public_key,
		    size_t peer_public_key_length);

/* Static function definitions --------------------------------------------- */

STATIC int comp_encapsulate(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* KEM encapsulate to the peer's encapsulation key G_X: the backend
	 * produces the KEM ciphertext G_Y (ctx->ephemeral.own.value), stores the shared
	 * secret G_XY as a handle (the shared-secret slot) and retains its
	 * ephemeral private key (the ephemeral slot) for the later static-DH
	 * G_IY agreement in message 3. For classical NIKE-as-KEM suites this
	 * wraps an ephemeral key generation plus a Diffie-Hellman agreement. */
	ctx->ephemeral.own.length = 0;
	const int ret = edhoc_crypto(ctx)->encapsulate(
		ctx->user_context, ctx->ephemeral.peer.value,
		ctx->ephemeral.peer.length,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_SHARED_SECRET),
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

STATIC int comp_decapsulate(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* KEM decapsulate the peer's ciphertext G_Y with the ephemeral private
	 * key handle from message 1; the shared secret G_XY is stored as a
	 * handle (the shared-secret slot). */
	const int ret = edhoc_crypto(ctx)->decapsulate(
		ctx->user_context,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
		ctx->ephemeral.peer.value, ctx->ephemeral.peer.length,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_SHARED_SECRET));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decapsulate: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_SHARED_SECRET);
	return EDHOC_SUCCESS;
}

STATIC int comp_th_2(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_1 != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state: %d, %d", EDHOC_TH_STATE_1,
			      ctx->state.th.stage);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* G_Y: own for the Responder, peer's for the Initiator. */
	const uint8_t *g_y = NULL;
	size_t g_y_len = 0;

	switch (ctx->state.role) {
	case EDHOC_ROLE_INITIATOR:
		g_y = ctx->ephemeral.peer.value;
		g_y_len = ctx->ephemeral.peer.length;
		break;
	case EDHOC_ROLE_RESPONDER:
		g_y = ctx->ephemeral.own.value;
		g_y_len = ctx->ephemeral.own.length;
		break;
	default:
		EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* TH_2 = H(G_Y, H(message_1)) streamed as CBOR byte-string segments:
	 * bstr(G_Y) || bstr(H(message_1)). ctx->state.th.value holds H(message_1) on input
	 * and receives TH_2 on output; the multipart update consumes it before
	 * hash_finish overwrites it. */
	const size_t h_msg_1_len = ctx->state.th.length;

	uint8_t g_y_hdr[EDHOC_CBOR_BSTR_HEAD_MAX_LEN] = { 0 };
	uint8_t h_msg_1_hdr[EDHOC_CBOR_BSTR_HEAD_MAX_LEN] = { 0 };

	const struct hash_segment segments[] = {
		{ g_y_hdr, edhoc_cbor_bstr_head_write(g_y_hdr, g_y_len) },
		{ g_y, g_y_len },
		{ h_msg_1_hdr,
		  edhoc_cbor_bstr_head_write(h_msg_1_hdr, h_msg_1_len) },
		{ ctx->state.th.value, h_msg_1_len },
	};

	ctx->state.th.length = csuite->hash_length;

	size_t hash_length = 0;
	const int ret = edhoc_comp_hash(ctx, segments, ARRAY_SIZE(segments),
					ctx->state.th.value,
					ctx->state.th.length, &hash_length);

	if (EDHOC_SUCCESS != ret || csuite->hash_length != hash_length) {
		EDHOC_LOG_ERR("TH_2 hash: %d, %zu, %zu", ret,
			      csuite->hash_length, hash_length);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->state.th.stage = EDHOC_TH_STATE_2;
	return EDHOC_SUCCESS;
}

STATIC int comp_prk_2e(struct edhoc_context *ctx)
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
	 * dedicated handle because it must outlive PRK_3e2m for KEYSTREAM_2; the
	 * shared secret and pseudorandom key are handles, only TH_2 is raw. */
	const int ret = edhoc_crypto(ctx)->extract(
		ctx->user_context,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_SHARED_SECRET),
		ctx->state.th.value, ctx->state.th.length,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_2E));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Extract PRK_2e: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_PRK_2E);
	ctx->state.prk_state = EDHOC_PRK_STATE_2E;
	return EDHOC_SUCCESS;
}

STATIC int comp_prk_3e2m(struct edhoc_context *ctx, const void *private_key_id,
			 const uint8_t *peer_public_key,
			 size_t peer_public_key_length)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_PRK_STATE_2E != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Invalid PRK state for PRK_3e2m: %d",
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	switch (ctx->negotiation.selected_method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_2:
		/* PRK_3e2m == PRK_2e: move PRK_2e's slot into PRK_3e2m so the
		 * shared key is owned by a single handle that lives into message
		 * 3. KEYSTREAM_2 reads PRK_3e2m for these methods. */
		edhoc_key_slot_move(ctx, EDHOC_KEY_SLOT_PRK_3E2M,
				    EDHOC_KEY_SLOT_PRK_2E);
		ctx->state.prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_3: {
		const size_t hash_len =
			edhoc_selected_cipher_suite(ctx)->hash_length;

		EDHOC_MEM_ALLOC(uint8_t, salt_3e2m, hash_len);
		if (NULL == salt_3e2m) {
			EDHOC_LOG_ERR("Memory allocation failed");
			return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
		}

		int ret = comp_salt_3e2m(ctx, salt_3e2m,
					 EDHOC_MEM_ALLOC_SIZE(salt_3e2m));

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute SALT_3e2m: %d", ret);
			EDHOC_MEM_FREE(salt_3e2m);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		EDHOC_LOG_HEXDUMP_DBG(salt_3e2m,
				      EDHOC_MEM_ALLOC_SIZE(salt_3e2m),
				      "SALT_3e2m");

		/* G_RX is a static-DH shared secret produced into its context
		 * slot; it is the IKM for EDHOC_Extract and is released with the
		 * other message 2 secrets (or by deinit on an error path). */
		ret = comp_grx(ctx, private_key_id, peer_public_key,
			       peer_public_key_length);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute G_RX: %d", ret);
			EDHOC_MEM_FREE(salt_3e2m);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		/* EDHOC_Extract(salt = SALT_3e2m, IKM = G_RX) -> PRK_3e2m in its
		 * own dedicated handle. SALT_3e2m is spent afterwards. */
		ret = edhoc_crypto(ctx)->extract(
			ctx->user_context,
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_G_RX), salt_3e2m,
			EDHOC_MEM_ALLOC_SIZE(salt_3e2m),
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M));

		edhoc_zeroize(ctx, salt_3e2m, EDHOC_MEM_ALLOC_SIZE(salt_3e2m));
		EDHOC_MEM_FREE(salt_3e2m);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Extract PRK_3e2m: %d", ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_PRK_3E2M);
		ctx->state.prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;
	}

	default:
		EDHOC_LOG_ERR("Invalid method");
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	EDHOC_LOG_ERR("Unsupported method: %d",
		      ctx->negotiation.selected_method);
	return EDHOC_ERROR_NOT_PERMITTED;
}

STATIC int comp_plaintext_2_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_2_len)
{
	if (NULL == ctx || NULL == mac_ctx || 0 == sign_len ||
	    NULL == plaintext_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	size_t len = 0;

	len += edhoc_connection_id_encoded_length(
		&ctx->negotiation.connection_id);

	if (0 != mac_ctx->id_cred_comp_len) {
		len += mac_ctx->id_cred_comp_len;
	} else {
		len += mac_ctx->id_cred_len;
	}

	len += sign_len;
	len += edhoc_cbor_bstr_head_length(sign_len);
	len += mac_ctx->ead_len;

	*plaintext_2_len = len;
	return EDHOC_SUCCESS;
}

STATIC int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t offset = 0;

	ret = edhoc_connection_id_encode(&ctx->negotiation.connection_id, ptxt,
					 ptxt_size, &offset);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc C_R");
		return ret;
	}

	if (0 != mac_ctx->id_cred_comp_len) {
		memcpy(&ptxt[offset], mac_ctx->id_cred_comp,
		       mac_ctx->id_cred_comp_len);
		offset += mac_ctx->id_cred_comp_len;
	} else {
		memcpy(&ptxt[offset], mac_ctx->id_cred, mac_ctx->id_cred_len);
		offset += mac_ctx->id_cred_len;
	}

	const struct zcbor_string cbor_sign_or_mac_2 = {
		.value = sign,
		.len = sign_len,
	};

	size_t len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&ptxt[offset], sign_len + edhoc_cbor_bstr_head_length(sign_len),
		&cbor_sign_or_mac_2, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc Signature_or_MAC_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	offset += len;

	if (mac_ctx->is_ead) {
		memcpy(&ptxt[offset], mac_ctx->ead, mac_ctx->ead_len);
		offset += mac_ctx->ead_len;
	}

	if (offset > ptxt_size) {
		EDHOC_LOG_ERR("Buffer too small for plaintext_2: %zu, %zu",
			      offset, ptxt_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*ptxt_len = offset;

	return EDHOC_SUCCESS;
}

STATIC int comp_keystream(const struct edhoc_context *ctx, uint8_t *keystream,
			  size_t keystream_len)
{
	if (NULL == ctx || NULL == keystream || 0 == keystream_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state for keystream_2: %d",
			      ctx->state.th.stage);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTREAM_2,
		.info_context.value = ctx->state.th.value,
		.info_context.len = ctx->state.th.length,
		.info_length = (uint32_t)keystream_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_head_length(
		EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTREAM_2);
	len += ctx->state.th.length +
	       edhoc_cbor_bstr_head_length(ctx->state.th.length);
	len += edhoc_cbor_int_head_length((int32_t)keystream_len);

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret || EDHOC_MEM_ALLOC_SIZE(info) != len) {
		EDHOC_LOG_ERR("CBOR enc info for keystream_2: %d, %zu, %zu",
			      ret, EDHOC_MEM_ALLOC_SIZE(info), len);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* EDHOC_Expand(PRK_2e, info) -> KEYSTREAM_2 (raw public output). For
	 * methods 0/2 PRK_2e was moved into PRK_3e2m, so read whichever handle
	 * still holds it. */
	const void *prk_2e_key_id =
		edhoc_key_slot_present(ctx, EDHOC_KEY_SLOT_PRK_2E) ?
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_2E) :
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M);
	ret = edhoc_crypto(ctx)->expand_raw(ctx->user_context, prk_2e_key_id,
					    info, EDHOC_MEM_ALLOC_SIZE(info),
					    keystream, keystream_len);
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand keystream_2: %d, %zu", ret,
			      keystream_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC void xor_arrays(uint8_t *dst, const uint8_t *src, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		dst[i] ^= src[i];
}

STATIC int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ctxt, size_t ctxt_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len)
{
	if (NULL == ctx || NULL == ctxt || 0 == ctxt_len || NULL == msg_2 ||
	    0 == msg_2_size || NULL == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t offset = 0;

	size_t len = 0;
	len += ctx->ephemeral.own.length;
	len += ctxt_len;

	EDHOC_MEM_ALLOC(uint8_t, buffer, len);
	if (NULL == buffer) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	memcpy(&buffer[offset], ctx->ephemeral.own.value,
	       ctx->ephemeral.own.length);
	offset += ctx->ephemeral.own.length;

	memcpy(&buffer[offset], ctxt, ctxt_len);
	offset += ctxt_len;

	if (EDHOC_MEM_ALLOC_SIZE(buffer) < offset) {
		EDHOC_LOG_ERR("Buffer overflow: %zu, %zu",
			      EDHOC_MEM_ALLOC_SIZE(buffer), offset);
		EDHOC_MEM_FREE(buffer);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	const struct zcbor_string cbor_msg_2 = {
		.value = buffer,
		.len = EDHOC_MEM_ALLOC_SIZE(buffer),
	};

	ret = cbor_encode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_size,
						     &cbor_msg_2, msg_2_len);
	EDHOC_MEM_FREE(buffer);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc msg_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_ciphertext_2_len(const struct edhoc_context *ctx,
				 const uint8_t *msg_2, size_t msg_2_len,
				 size_t *ctxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec msg_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	if (len > msg_2_len) {
		EDHOC_LOG_ERR("Decoded length exceeds buffer: %zu, %zu", len,
			      msg_2_len);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	const size_t g_y_len =
		edhoc_selected_cipher_suite(ctx)->kem_ciphertext_length;

	if (dec_msg_2.len <= g_y_len) {
		EDHOC_LOG_ERR("Decoded message_2 too short for G_Y: %zu, %zu",
			      dec_msg_2.len, g_y_len);
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;
	}

	len = dec_msg_2.len - g_y_len;

	*ctxt_len = len;
	return EDHOC_SUCCESS;
}

STATIC int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR decode message_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	if (len > msg_2_len) {
		EDHOC_LOG_ERR("Message 2 length mismatch: %zu, %zu", len,
			      msg_2_len);
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;
	}

	/* Get Diffie-Hellmann peer public key (G_Y). */
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);
	ctx->ephemeral.peer.length = csuite->kem_ciphertext_length;
	memcpy(ctx->ephemeral.peer.value, dec_msg_2.value,
	       ctx->ephemeral.peer.length);

	/* Get CIPHERTEXT_2. */
	const size_t offset = ctx->ephemeral.peer.length;
	memcpy(ctxt_2, &dec_msg_2.value[offset], ctxt_2_len);

	return EDHOC_SUCCESS;
}

STATIC int parse_plaintext_2(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len, struct plaintext *parsed_ptxt)
{
	if (NULL == ctx || NULL == ptxt || 0 == ptxt_len ||
	    NULL == parsed_ptxt) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_2 cbor_ptxt_2 = { 0 };
	ret = cbor_decode_plaintext_2(ptxt, ptxt_len, &cbor_ptxt_2, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec plaintext_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* C_R */
	switch (cbor_ptxt_2.plaintext_2_C_R_choice) {
	case plaintext_2_C_R_int_c:
		if (EDHOC_SUCCESS !=
		    edhoc_connection_id_from_int(
			    cbor_ptxt_2.plaintext_2_C_R_int,
			    &ctx->negotiation.peer_connection_id)) {
			EDHOC_LOG_ERR("C_R int out of range: %d",
				      cbor_ptxt_2.plaintext_2_C_R_int);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case plaintext_2_C_R_bstr_c:
		if (EDHOC_SUCCESS !=
		    edhoc_connection_id_from_bstr(
			    cbor_ptxt_2.plaintext_2_C_R_bstr.value,
			    cbor_ptxt_2.plaintext_2_C_R_bstr.len,
			    &ctx->negotiation.peer_connection_id)) {
			EDHOC_LOG_ERR("C_R bstr too large: %zu",
				      cbor_ptxt_2.plaintext_2_C_R_bstr.len);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}
		break;

	default:
		EDHOC_LOG_ERR("Invalid C_R choice: %d",
			      cbor_ptxt_2.plaintext_2_C_R_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* ID_CRED_R */
	switch (cbor_ptxt_2.plaintext_2_ID_CRED_R_choice) {
	case plaintext_2_ID_CRED_R_int_c:
		ret = edhoc_credential_parse_kid_int(
			cbor_ptxt_2.plaintext_2_ID_CRED_R_int,
			&parsed_ptxt->kid_byte,
			&parsed_ptxt->peer_credential_id);
		break;

	case plaintext_2_ID_CRED_R_bstr_c:
		ret = edhoc_credential_parse_kid_bstr(
			cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.value,
			cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.len,
			&parsed_ptxt->peer_credential_id);
		break;

	case plaintext_2_ID_CRED_R_map_m_c:
		ret = edhoc_credential_parse_map(
			&cbor_ptxt_2.plaintext_2_ID_CRED_R_map_m,
			&parsed_ptxt->peer_credential_id);
		break;

	default:
		EDHOC_LOG_ERR("Invalid ID_CRED_R choice: %d",
			      cbor_ptxt_2.plaintext_2_ID_CRED_R_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse ID_CRED_R: %d", ret);
		return ret;
	}

	/* Sign_or_MAC_2 */
	parsed_ptxt->sign_or_mac.value =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.value;
	parsed_ptxt->sign_or_mac.length =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.len;

	/* EAD_2 if present */
	if (cbor_ptxt_2.plaintext_2_EAD_2_m_present) {
		if (edhoc_ead_capacity(ctx) <
		    cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2_count) {
			EDHOC_LOG_ERR(
				"EAD buffer too small: %zu, %zu",
				cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2_count,
				edhoc_ead_capacity(ctx));
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		ctx->ead.count = cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2_count;

		for (size_t i = 0; i < ctx->ead.count; ++i) {
			const struct ead_y *token =
				&cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i];

			ctx->ead.token[i].label = token->ead_y_ead_label;

			/* zcbor keeps the length read from a bstr header even
			 * when the value itself did not fit in the payload, so
			 * only the presence flag may be trusted here. */
			if (token->ead_y_ead_value_present) {
				ctx->ead.token[i].value.value =
					token->ead_y_ead_value.value;
				ctx->ead.token[i].value.length =
					token->ead_y_ead_value.len;
			} else {
				ctx->ead.token[i].value.value = NULL;
				ctx->ead.token[i].value.length = 0;
			}
		}
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == ptxt || 0 == ptxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state: %d", ctx->state.th.stage);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) streamed as:
	 * bstr(TH_2) || PLAINTEXT_2 || CRED_R. ctx->state.th.value holds TH_2 on input and
	 * receives TH_3 on output; the multipart update consumes it before
	 * hash_finish overwrites it. */
	const size_t th_2_len = ctx->state.th.length;

	uint8_t th_2_hdr[EDHOC_CBOR_BSTR_HEAD_MAX_LEN] = { 0 };

	const struct hash_segment segments[] = {
		{ th_2_hdr, edhoc_cbor_bstr_head_write(th_2_hdr, th_2_len) },
		{ ctx->state.th.value, th_2_len },
		{ ptxt, ptxt_len },
		{ mac_ctx->cred, mac_ctx->cred_len },
	};

	ctx->state.th.length = edhoc_selected_cipher_suite(ctx)->hash_length;

	size_t hash_len = 0;
	const int ret = edhoc_comp_hash(ctx, segments, ARRAY_SIZE(segments),
					ctx->state.th.value,
					ctx->state.th.length, &hash_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Hash TH_3: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->state.th.stage = EDHOC_TH_STATE_3;
	return EDHOC_SUCCESS;
}

STATIC int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_2E != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->state.th.stage,
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	const size_t hash_len = edhoc_selected_cipher_suite(ctx)->hash_length;

	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M,
		.info_context.value = ctx->state.th.value,
		.info_context.len = ctx->state.th.length,
		.info_length = (uint32_t)hash_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_head_length(
		EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M);
	len += ctx->state.th.length +
	       edhoc_cbor_bstr_head_length(ctx->state.th.length);
	len += edhoc_cbor_int_head_length((int32_t)hash_len);

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret || EDHOC_MEM_ALLOC_SIZE(info) != len) {
		EDHOC_LOG_ERR("CBOR enc info for salt_3e2m: %d, %zu, %zu", ret,
			      EDHOC_MEM_ALLOC_SIZE(info), len);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* EDHOC_Expand(PRK_2e, info) -> SALT_3e2m (raw). */
	ret = edhoc_crypto(ctx)->expand_raw(
		ctx->user_context,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_2E), info,
		EDHOC_MEM_ALLOC_SIZE(info), salt, salt_len);
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand salt_3e2m: %d, %zu", ret, salt_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_grx(struct edhoc_context *ctx, const void *private_key_id,
		    const uint8_t *peer_public_key,
		    size_t peer_public_key_length)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	void *grx_key_id = edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_G_RX);
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (ctx->state.role) {
	case EDHOC_ROLE_INITIATOR:
		if (NULL == peer_public_key || 0 == peer_public_key_length) {
			EDHOC_LOG_ERR("Missing peer authentication key");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		/* G_RX = key_agreement(ephemeral private key, R's static public
		 * key). The shared secret is produced as a handle. */
		ret = edhoc_crypto(ctx)->key_agreement(
			ctx->user_context,
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
			peer_public_key, peer_public_key_length, grx_key_id);
		break;

	case EDHOC_ROLE_RESPONDER:
		if (NULL == private_key_id) {
			EDHOC_LOG_ERR("Missing local authentication key");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		/* G_RX = key_agreement(R's static private key, peer's ephemeral
		 * public key G_X). */
		ret = edhoc_crypto(ctx)->key_agreement(
			ctx->user_context, private_key_id,
			ctx->ephemeral.peer.value, ctx->ephemeral.peer.length,
			grx_key_id);
		break;

	default:
		EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Key agreement for G_RX: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_G_RX);
	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 2:
 *	1.  KEM encapsulate to the peer's G_X (produce G_Y and G_XY).
 *	2.  Compute Transcript Hash 2 (TH_2).
 *	3.  Compute Pseudo Random Key 2 (PRK_2e).
 *	4.  Fetch authentication credentials.
 *	5.  Compose EAD_2 if present.
 *	6.  Compute pseudorandom key (PRK_3e2m).
 *	7a. Compute required buffer length for context_2.
 *	7b. Cborise items required by context_2.
 *	7c. Compute Message Authentication Code (MAC_2).
 *	8.  Compute signature if needed (Signature_or_MAC_2).
 *	9.  Prepare plaintext (PLAINTEXT_2).
 *	10. Compute key stream (KEYSTREAM_2).
 *	11. Compute Transcript Hash 3 (TH_3).
 *	12. Compute ciphertext (CIPHERTEXT_2).
 *	13. Cborise items for message 2.
 *	14. Release the message-2 scoped secrets (PRK_3e2m lives on).
 *	15. Clean-up EAD tokens.
 */
int edhoc_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
			    size_t msg_2_size, size_t *msg_2_len)
{
	EDHOC_LOG_INF("Compose msg2 start");

	if (NULL == ctx || msg_2 == NULL || 0 == msg_2_size ||
	    NULL == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_RECEIVED_M1 != ctx->state.machine ||
	    EDHOC_TH_STATE_1 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_INVALID != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_2;
	ctx->state.role = EDHOC_ROLE_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. KEM encapsulate to the peer's G_X: produce the KEM ciphertext G_Y
	 * (sent in message 2) and the shared-secret handle. */
	ret = comp_encapsulate(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encapsulate: %d", ret);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->ephemeral.own.value,
			      ctx->ephemeral.own.length, "G_Y");

	/* 2. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_2: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_2");

	/* 3. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = comp_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_2e: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 4. Select authentication credential. */
	const struct edhoc_call_context cred_call_context =
		edhoc_call_context(ctx);
	struct edhoc_credential_selected selected = { 0 };
	ret = ctx->interfaces.cred.select_local(ctx->user_context,
						&cred_call_context, &selected);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Select local credential: %d", ret);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	ret = edhoc_credential_validate_selected(&selected);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Validate selected credential: %d", ret);
		return ret;
	}

	/* 5. Compose EAD_2 if present. */
	if (edhoc_ead_may_compose(ctx)) {
		const struct edhoc_call_context call_context =
			edhoc_call_context(ctx);

		ret = ctx->interfaces.ead.compose(ctx->user_context,
						  &call_context, ctx->ead.token,
						  edhoc_ead_capacity(ctx),
						  &ctx->ead.count);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("EAD_2 compose: %d", ret);
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
		}

		ret = edhoc_validate_ead_composed(ctx->ead.token,
						  ctx->ead.count);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}
	}

	/* 6. Compute pseudorandom key (PRK_3e2m). */
	ret = comp_prk_3e2m(ctx, selected.private_key_id, NULL, 0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 7a. Compute required buffer length for context_2. */
	struct edhoc_credential_material material = { 0 };
	ret = edhoc_credential_material_from_selected(&selected, &material);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	size_t mac_ctx_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &material, &mac_ctx_len);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	/* 7b. Cborise items required by context_2. */
	EDHOC_MEM_ALLOC(uint8_t, mac_ctx_buf,
			sizeof(struct mac_context) + mac_ctx_len);
	if (NULL == mac_ctx_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_ctx_len;

	ret = edhoc_comp_mac_context(ctx, &material, mac_ctx);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->conn_id, mac_ctx->conn_id_len, "C_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->id_cred, mac_ctx->id_cred_len,
			      "ID_CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->th, mac_ctx->th_len, "TH_2");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->cred, mac_ctx->cred_len, "CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->buf, mac_ctx->buf_len, "context_2");

	/* 7c. Compute Message Authentication Code (MAC_2). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);
	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_comp_mac(ctx, mac_ctx, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	/* 8. Compute signature if needed (Signature_or_MAC_2). */
	size_t sign_or_mac_length = 0;
	ret = edhoc_comp_sign_or_mac_length(ctx, &sign_or_mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	size_t signature_length = 0;
	EDHOC_MEM_ALLOC(uint8_t, signature, sign_or_mac_length);
	if (NULL == signature) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_comp_sign_or_mac(ctx, selected.private_key_id, mac_ctx,
				     mac_buf, mac_length, signature,
				     EDHOC_MEM_ALLOC_SIZE(signature),
				     &signature_length);
	EDHOC_MEM_FREE(mac_buf);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(signature, signature_length,
			      "Signature_or_MAC_2");

	/* 9. Prepare plaintext (PLAINTEXT_2). */
	size_t plaintext_len = 0;
	ret = comp_plaintext_2_len(ctx, mac_ctx, signature_length,
				   &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute plaintext_2 length: %d", ret);
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	EDHOC_MEM_ALLOC(uint8_t, plaintext, plaintext_len);
	if (NULL == plaintext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	plaintext_len = 0;
	ret = prepare_plaintext_2(ctx, mac_ctx, signature, signature_length,
				  plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext),
				  &plaintext_len);
	EDHOC_MEM_FREE(signature);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare plaintext_2: %d", ret);
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_2");

	/* 10. Compute key stream (KEYSTREAM_2). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, plaintext_len);
	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = comp_keystream(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute keystream_2: %d", ret);
		EDHOC_MEM_FREE(keystream);
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_2");

	/* 11. Compute Transcript Hash 3 (TH_3). */
	ret = comp_th_3(ctx, mac_ctx, plaintext, plaintext_len);
	EDHOC_MEM_FREE(mac_ctx_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_3: %d", ret);
		EDHOC_MEM_FREE(keystream);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_3");

	/* 12. Compute ciphertext (CIPHERTEXT_2). */
	xor_arrays(plaintext, keystream, plaintext_len);
	EDHOC_MEM_FREE(keystream);
	const uint8_t *ciphertext = plaintext;
	const size_t ciphertext_len = plaintext_len;

	EDHOC_LOG_HEXDUMP_DBG(ciphertext, ciphertext_len, "CIPHERTEXT_2");

	/* 13. Cborise items for message 2. */
	ret = prepare_message_2(ctx, ciphertext, ciphertext_len, msg_2,
				msg_2_size, msg_2_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare message_2: %d", ret);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_MEM_FREE(plaintext);

	EDHOC_LOG_HEXDUMP_DBG(msg_2, *msg_2_len, "message_2");
	EDHOC_LOG_INF("Compose msg2 end");

	/* 14. Release the message-2 scoped secrets (PRK_3e2m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 2 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 15. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_WAIT_M3;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 2:
 * 	1.  Compute required length for ciphertext.
 *      2.  Decode cborised message 2.
 *      3.  Compute Diffie-Hellmann shared secret (G_XY).
 *      4.  Compute Transcript Hash 2 (TH_2).
 *      5.  Compute Pseudo Random Key 2 (PRK_2e).
 *      6.  Compute key stream (KEYSTREAM_2).
 *      7.  Compute plaintext (PLAINTEXT_2).
 *      8.  Parse plaintext (PLAINTEXT_2).
 *      9.  Process EAD if present.
 *      10. Verify if credentials from peer are trusted.
 *      11. Compute pseudorandom key (PRK_3e2m).
 *      12. Compute required buffer length for context_2.
 *      13. Cborise items required by context_2.
 *      14. Compute Message Authentication Code (MAC_2).
 *      15. Verify Signature_or_MAC_2.
 *      16. Compute Transcript Hash 3 (TH_3).
 *      17. Release the message-2 scoped secrets (PRK_3e2m lives on).
 *      18. Clean-up EAD tokens.
 */
int edhoc_message_2_process(struct edhoc_context *ctx, const uint8_t *msg_2,
			    size_t msg_2_len)
{
	EDHOC_LOG_INF("Process msg2 start");

	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_WAIT_M2 != ctx->state.machine ||
	    EDHOC_TH_STATE_1 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_INVALID != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_2;
	ctx->state.role = EDHOC_ROLE_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* 1. Compute required length for ciphertext. */
	ret = comp_ciphertext_2_len(ctx, msg_2, msg_2_len, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute ciphertext length: %d", ret);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	EDHOC_MEM_ALLOC(uint8_t, ciphertext_2, len);
	if (NULL == ciphertext_2) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	/* 2. Decode cborised message 2. */
	ret = parse_msg_2(ctx, msg_2, msg_2_len, ciphertext_2,
			  EDHOC_MEM_ALLOC_SIZE(ciphertext_2));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse msg2: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ciphertext_2, EDHOC_MEM_ALLOC_SIZE(ciphertext_2),
			      "CIPHERTEXT_2");

	/* 3. KEM decapsulate the peer's G_Y into the shared-secret handle. */
	ret = comp_decapsulate(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decapsulate: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_2: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_2");

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = comp_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_2e: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 6. Compute key stream (KEYSTREAM_2). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, EDHOC_MEM_ALLOC_SIZE(ciphertext_2));
	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = comp_keystream(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute keystream: %d", ret);
		EDHOC_MEM_FREE(keystream);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_2");

	/* 7. Compute plaintext (PLAINTEXT_2). */
	xor_arrays(ciphertext_2, keystream, EDHOC_MEM_ALLOC_SIZE(ciphertext_2));
	EDHOC_MEM_FREE(keystream);
	const uint8_t *plaintext = ciphertext_2;
	const size_t plaintext_len = EDHOC_MEM_ALLOC_SIZE(ciphertext_2);

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_2");

	/* 8. Parse plaintext (PLAINTEXT_2). */
	struct plaintext parsed_ptxt = { 0 };
	ret = parse_plaintext_2(ctx, plaintext, plaintext_len, &parsed_ptxt);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse plaintext: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->negotiation.peer_connection_id.value,
			      ctx->negotiation.peer_connection_id.length,
			      "C_R");

	/* 9. Process EAD if present. */
	if (edhoc_ead_may_process(ctx)) {
		const struct edhoc_call_context call_context =
			edhoc_call_context(ctx);

		ret = ctx->interfaces.ead.process(ctx->user_context,
						  &call_context, ctx->ead.token,
						  ctx->ead.count);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("EAD_2 process: %d", ret);
			EDHOC_MEM_FREE(ciphertext_2);
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}

		for (size_t i = 0; i < ctx->ead.count; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead.token[i].label,
				sizeof(ctx->ead.token[i].label),
				"EAD_2 process label");

			if (0 != ctx->ead.token[i].value.length) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead.token[i].value.value,
					ctx->ead.token[i].value.length,
					"EAD_2 process value");
			}
		}
	}

	/* 10. Verify if credentials from peer are trusted. */
	const struct edhoc_call_context call_context = edhoc_call_context(ctx);
	struct edhoc_credential_trusted trusted = { 0 };

	ret = ctx->interfaces.cred.authenticate_peer(
		ctx->user_context, &call_context,
		&parsed_ptxt.peer_credential_id, &trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Credentials verification: %d", ret);
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	ret = edhoc_credential_validate_trusted(&parsed_ptxt.peer_credential_id,
						&trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Validate trusted credentials: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	/* 11. Compute pseudorandom key (PRK_3e2m). */
	ret = comp_prk_3e2m(ctx, NULL, trusted.public_key.value,
			    trusted.public_key.length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 12. Compute required buffer length for context_2. */
	struct edhoc_credential_material material = { 0 };
	ret = edhoc_credential_material_from_trusted(
		&parsed_ptxt.peer_credential_id, &trusted, &material);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	size_t mac_context_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &material, &mac_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context length: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	/* 13. Cborise items required by context_2. */
	EDHOC_MEM_ALLOC(uint8_t, mac_ctx_buf,
			sizeof(struct mac_context) + mac_context_len);
	if (NULL == mac_ctx_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_context_len;

	ret = edhoc_comp_mac_context(ctx, &material, mac_ctx);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->conn_id, mac_ctx->conn_id_len, "C_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->id_cred, mac_ctx->id_cred_len,
			      "ID_CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->th, mac_ctx->th_len, "TH_2");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->cred, mac_ctx->cred_len, "CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->buf, mac_ctx->buf_len, "context_2");

	/* 14. Compute Message Authentication Code (MAC_2). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);
	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_comp_mac(ctx, mac_ctx, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	/* 15. Verify Signature_or_MAC_2. */
	ret = edhoc_verify_sign_or_mac(ctx, mac_ctx, trusted.public_key.value,
				       trusted.public_key.length,
				       parsed_ptxt.sign_or_mac.value,
				       parsed_ptxt.sign_or_mac.length, mac_buf,
				       mac_length);
	EDHOC_MEM_FREE(mac_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Signature or MAC_2 verification: %d", ret);
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;
	}

	/* 16. Compute Transcript Hash 3 (TH_3). */
	ret = comp_th_3(ctx, mac_ctx, plaintext, plaintext_len);
	EDHOC_MEM_FREE(mac_ctx_buf);
	EDHOC_MEM_FREE(ciphertext_2);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_3: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_3");
	EDHOC_LOG_INF("Process msg2 end");

	/* 17. Release the message-2 scoped secrets (PRK_3e2m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 2 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 18. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
