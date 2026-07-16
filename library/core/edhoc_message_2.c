/**
 * \file    edhoc_message_2.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 2 compose & process.
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_common_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wreserved-identifier"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_message_2_encode.h>
#include <backend_cbor_message_2_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_bstr_type_decode.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_int_type_decode.h>
#include <backend_cbor_id_cred_x_encode.h>
#include <backend_cbor_id_cred_x_decode.h>
#include <backend_cbor_sig_structure_encode.h>
#include <backend_cbor_info_encode.h>
#include <backend_cbor_plaintext_2_decode.h>
#include <backend_cbor_ead_encode.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** 
 * \brief KEM encapsulate to the peer's G_X (Responder): produce the KEM
 *        ciphertext G_Y (into \p ctx->pub_eph_key) and the ephemeral
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
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public static DH key. 
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_prk_3e2m(struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len);

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
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public key.
 * \param pub_key_len           Peer public key length.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_grx(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len);

/* Static function definitions --------------------------------------------- */

STATIC int comp_encapsulate(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* KEM encapsulate to the peer's encapsulation key G_X: the backend
	 * produces the KEM ciphertext G_Y (ctx->pub_eph_key), stores the shared
	 * secret G_XY as a handle (the shared-secret slot) and retains its
	 * ephemeral private key (the ephemeral slot) for the later static-DH
	 * G_IY agreement in message 3. For classical NIKE-as-KEM suites this
	 * wraps an ephemeral key generation plus a Diffie-Hellman agreement. */
	ctx->pub_eph_key_len = 0;
	const int ret = ctx->itf.crypto.encapsulate(
		ctx->user_ctx, ctx->peer_pub_eph_key, ctx->peer_pub_eph_key_len,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_SHARED_SECRET),
		ctx->pub_eph_key, sizeof(ctx->pub_eph_key),
		&ctx->pub_eph_key_len);

	if (EDHOC_SUCCESS != ret ||
	    csuite.kem_ciphertext_length != ctx->pub_eph_key_len) {
		EDHOC_LOG_ERR("Encapsulate: %d, %zu, %zu", ret,
			      csuite.kem_ciphertext_length,
			      ctx->pub_eph_key_len);
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
	const int ret = ctx->itf.crypto.decapsulate(
		ctx->user_ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
		ctx->peer_pub_eph_key, ctx->peer_pub_eph_key_len,
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

	if (EDHOC_TH_STATE_1 != ctx->th_state) {
		EDHOC_LOG_ERR("Invalid TH state: %d, %d", EDHOC_TH_STATE_1,
			      ctx->th_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* G_Y: own for the Responder, peer's for the Initiator. */
	const uint8_t *g_y = NULL;
	size_t g_y_len = 0;

	switch (ctx->role) {
	case EDHOC_INITIATOR:
		g_y = ctx->peer_pub_eph_key;
		g_y_len = ctx->peer_pub_eph_key_len;
		break;
	case EDHOC_RESPONDER:
		g_y = ctx->pub_eph_key;
		g_y_len = ctx->pub_eph_key_len;
		break;
	default:
		EDHOC_LOG_ERR("Invalid role: %d", ctx->role);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* TH_2 = H(G_Y, H(message_1)) streamed as CBOR byte-string segments:
	 * bstr(G_Y) || bstr(H(message_1)). ctx->th holds H(message_1) on input
	 * and receives TH_2 on output; the multipart update consumes it before
	 * hash_finish overwrites it. */
	const size_t h_msg_1_len = ctx->th_len;

	uint8_t g_y_hdr[EDHOC_CBOR_BSTR_HEADER_MAX_LEN] = { 0 };
	uint8_t h_msg_1_hdr[EDHOC_CBOR_BSTR_HEADER_MAX_LEN] = { 0 };

	const struct hash_segment segments[] = {
		{ g_y_hdr, edhoc_cbor_bstr_header(g_y_hdr, g_y_len) },
		{ g_y, g_y_len },
		{ h_msg_1_hdr,
		  edhoc_cbor_bstr_header(h_msg_1_hdr, h_msg_1_len) },
		{ ctx->th, h_msg_1_len },
	};

	ctx->th_len = csuite.hash_length;

	size_t hash_length = 0;
	const int ret = edhoc_comp_hash(ctx, segments, ARRAY_SIZE(segments),
					ctx->th, ctx->th_len, &hash_length);

	if (EDHOC_SUCCESS != ret || csuite.hash_length != hash_length) {
		EDHOC_LOG_ERR("TH_2 hash: %d, %zu, %zu", ret,
			      csuite.hash_length, hash_length);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->th_state = EDHOC_TH_STATE_2;
	return EDHOC_SUCCESS;
}

STATIC int comp_prk_2e(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state) {
		EDHOC_LOG_ERR("Invalid state for PRK_2e: %d, %d", ctx->th_state,
			      ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* EDHOC_Extract(salt = TH_2, IKM = G_XY) -> PRK_2e. PRK_2e has its own
	 * dedicated handle because it must outlive PRK_3e2m for KEYSTREAM_2; the
	 * shared secret and pseudorandom key are handles, only TH_2 is raw. */
	const int ret = ctx->itf.crypto.extract(
		ctx->user_ctx,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_SHARED_SECRET), ctx->th,
		ctx->th_len, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_2E));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Extract PRK_2e: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_PRK_2E);
	ctx->prk_state = EDHOC_PRK_STATE_2E;
	return EDHOC_SUCCESS;
}

STATIC int comp_prk_3e2m(struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_PRK_STATE_2E != ctx->prk_state) {
		EDHOC_LOG_ERR("Invalid PRK state for PRK_3e2m: %d",
			      ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	switch (ctx->chosen_method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_2:
		/* PRK_3e2m == PRK_2e: move PRK_2e's slot into PRK_3e2m so the
		 * shared key is owned by a single handle that lives into message
		 * 3. KEYSTREAM_2 reads PRK_3e2m for these methods. */
		edhoc_key_slot_move(ctx, EDHOC_KEY_SLOT_PRK_3E2M,
				    EDHOC_KEY_SLOT_PRK_2E);
		ctx->prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_3: {
		const size_t hash_len =
			ctx->csuite[ctx->chosen_csuite_idx].hash_length;

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
		ret = comp_grx(ctx, auth_cred, pub_key, pub_key_len);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute G_RX: %d", ret);
			EDHOC_MEM_FREE(salt_3e2m);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		/* EDHOC_Extract(salt = SALT_3e2m, IKM = G_RX) -> PRK_3e2m in its
		 * own dedicated handle. SALT_3e2m is spent afterwards. */
		ret = ctx->itf.crypto.extract(
			ctx->user_ctx,
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_G_RX), salt_3e2m,
			EDHOC_MEM_ALLOC_SIZE(salt_3e2m),
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M));

		ctx->itf.platform.zeroize(salt_3e2m,
					  EDHOC_MEM_ALLOC_SIZE(salt_3e2m));
		EDHOC_MEM_FREE(salt_3e2m);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Extract PRK_3e2m: %d", ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_PRK_3E2M);
		ctx->prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;
	}

	case EDHOC_METHOD_MAX:
		EDHOC_LOG_ERR("Invalid method");
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	EDHOC_LOG_ERR("Unsupported method: %d", ctx->chosen_method);
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

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		len += edhoc_cbor_int_mem_req(ctx->cid.int_value);
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		len += ctx->cid.bstr_length;
		len += edhoc_cbor_bstr_oh(ctx->cid.bstr_length);
		break;
	}

	if (true == mac_ctx->id_cred_is_comp_enc) {
		switch (mac_ctx->id_cred_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			len += edhoc_cbor_int_mem_req(mac_ctx->id_cred_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			len += mac_ctx->id_cred_bstr_len;
			len += edhoc_cbor_bstr_oh(mac_ctx->id_cred_bstr_len);
			break;
		}
	} else {
		len += mac_ctx->id_cred_len;
	}

	len += sign_len;
	len += edhoc_cbor_bstr_oh(sign_len);
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

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
		size_t len = 0;
		/* NOLINTNEXTLINE(bugprone-signed-char-misuse,cert-str34-c) */
		const int32_t value = ctx->cid.int_value;
		ret = cbor_encode_integer_type_int_type(
			ptxt, ptxt_size - offset, &value, &len);

		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("CBOR enc C_I int");
			return EDHOC_ERROR_CBOR_FAILURE;
		}

		offset += len;
		break;
	}
	case EDHOC_CID_TYPE_BYTE_STRING: {
		size_t len = 0;
		const struct zcbor_string input = {
			.value = ctx->cid.bstr_value,
			.len = ctx->cid.bstr_length,
		};
		ret = cbor_encode_byte_string_type_bstr_type(
			ptxt, ptxt_size - offset, &input, &len);

		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("CBOR enc C_I bstr");
			return EDHOC_ERROR_CBOR_FAILURE;
		}

		offset += len;
		break;
	}
	default:
		EDHOC_LOG_ERR("Invalid C_I enc type: %d", ctx->cid.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (mac_ctx->id_cred_is_comp_enc) {
		switch (mac_ctx->id_cred_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			memcpy(&ptxt[offset], &mac_ctx->id_cred_int, 1);
			offset += 1;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			memcpy(&ptxt[offset], &mac_ctx->id_cred_bstr,
			       mac_ctx->id_cred_bstr_len);
			offset += mac_ctx->id_cred_bstr_len;
			break;
		default:
			EDHOC_LOG_ERR("Invalid ID_CRED_R enc type: %d",
				      mac_ctx->id_cred_enc_type);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
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
		&ptxt[offset], sign_len + edhoc_cbor_bstr_oh(sign_len),
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

	if (EDHOC_TH_STATE_2 != ctx->th_state) {
		EDHOC_LOG_ERR("Invalid TH state for keystream_2: %d",
			      ctx->th_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTREAM_2,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)keystream_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTREAM_2);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += edhoc_cbor_int_mem_req((int32_t)keystream_len);

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
	ret = ctx->itf.crypto.expand_raw(ctx->user_ctx, prk_2e_key_id, info,
					 EDHOC_MEM_ALLOC_SIZE(info), keystream,
					 keystream_len);
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
	len += ctx->pub_eph_key_len;
	len += ctxt_len;

	EDHOC_MEM_ALLOC(uint8_t, buffer, len);
	if (NULL == buffer) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	memcpy(&buffer[offset], ctx->pub_eph_key, ctx->pub_eph_key_len);
	offset += ctx->pub_eph_key_len;

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
		ctx->csuite[ctx->chosen_csuite_idx].kem_ciphertext_length;

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
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];
	ctx->peer_pub_eph_key_len = csuite.kem_ciphertext_length;
	memcpy(ctx->peer_pub_eph_key, dec_msg_2.value,
	       ctx->peer_pub_eph_key_len);

	/* Get CIPHERTEXT_2. */
	const size_t offset = ctx->peer_pub_eph_key_len;
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
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    (int8_t)cbor_ptxt_2.plaintext_2_C_R_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    (int8_t)cbor_ptxt_2.plaintext_2_C_R_int) {
			EDHOC_LOG_ERR("C_R int out of range: %d",
				      (int8_t)cbor_ptxt_2.plaintext_2_C_R_int);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx->peer_cid.int_value =
			(int8_t)cbor_ptxt_2.plaintext_2_C_R_int;
		break;

	case plaintext_2_C_R_bstr_c:
		if (ARRAY_SIZE(ctx->peer_cid.bstr_value) <
		    cbor_ptxt_2.plaintext_2_C_R_bstr.len) {
			EDHOC_LOG_ERR("C_R bstr too large: %zu",
				      cbor_ptxt_2.plaintext_2_C_R_bstr.len);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
		ctx->peer_cid.bstr_length =
			cbor_ptxt_2.plaintext_2_C_R_bstr.len;
		memcpy(ctx->peer_cid.bstr_value,
		       cbor_ptxt_2.plaintext_2_C_R_bstr.value,
		       cbor_ptxt_2.plaintext_2_C_R_bstr.len);
		break;

	default:
		EDHOC_LOG_ERR("Invalid C_R choice: %d",
			      cbor_ptxt_2.plaintext_2_C_R_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* ID_CRED_R */
	switch (cbor_ptxt_2.plaintext_2_ID_CRED_R_choice) {
	case plaintext_2_ID_CRED_R_int_c:
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_INTEGER;
		parsed_ptxt->auth_cred.key_id.key_id_int =
			cbor_ptxt_2.plaintext_2_ID_CRED_R_int;
		break;

	case plaintext_2_ID_CRED_R_bstr_c:
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_BYTE_STRING;
		parsed_ptxt->auth_cred.key_id.key_id_bstr_length =
			cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.len;
		memcpy(parsed_ptxt->auth_cred.key_id.key_id_bstr,
		       cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.value,
		       cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.len);
		break;

	case plaintext_2_ID_CRED_R_map_m_c: {
		const struct map *cbor_map =
			&cbor_ptxt_2.plaintext_2_ID_CRED_R_map_m;

		if (cbor_map->map_x5chain_present) {
			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_CHAIN;

			const struct COSE_X509_r *cose_x509 =
				&cbor_map->map_x5chain.map_x5chain;

			switch (cose_x509->COSE_X509_choice) {
			case COSE_X509_bstr_c:
				parsed_ptxt->auth_cred.x509_chain.nr_of_certs =
					1;
				parsed_ptxt->auth_cred.x509_chain.cert[0] =
					cose_x509->COSE_X509_bstr.value;
				parsed_ptxt->auth_cred.x509_chain.cert_len[0] =
					cose_x509->COSE_X509_bstr.len;
				break;
			case COSE_X509_certs_l_c: {
				if (ARRAY_SIZE(parsed_ptxt->auth_cred.x509_chain
						       .cert) <
				    cose_x509->COSE_X509_certs_l_certs_count) {
					EDHOC_LOG_ERR(
						"X.509 certificate chain too large: %zu (max %zu)",
						cose_x509->COSE_X509_certs_l_certs_count,
						ARRAY_SIZE(
							parsed_ptxt->auth_cred
								.x509_chain
								.cert));
					return EDHOC_ERROR_BUFFER_TOO_SMALL;
				}

				parsed_ptxt->auth_cred.x509_chain.nr_of_certs =
					cose_x509->COSE_X509_certs_l_certs_count;

				for (size_t i = 0;
				     i <
				     cose_x509->COSE_X509_certs_l_certs_count;
				     ++i) {
					parsed_ptxt->auth_cred.x509_chain
						.cert[i] =
						cose_x509
							->COSE_X509_certs_l_certs
								[i]
							.value;
					parsed_ptxt->auth_cred.x509_chain
						.cert_len[i] =
						cose_x509
							->COSE_X509_certs_l_certs
								[i]
							.len;
				}
				break;
			}

			default:
				EDHOC_LOG_ERR("Invalid COSE_X509 choice: %d",
					      cose_x509->COSE_X509_choice);
				return EDHOC_ERROR_NOT_PERMITTED;
			}
		}

		if (cbor_map->map_x5t_present) {
			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_HASH;

			const struct COSE_CertHash *cose_x509 =
				&cbor_map->map_x5t.map_x5t;

			parsed_ptxt->auth_cred.x509_hash.cert_fp =
				cose_x509->COSE_CertHash_hashValue.value;
			parsed_ptxt->auth_cred.x509_hash.cert_fp_len =
				cose_x509->COSE_CertHash_hashValue.len;

			switch (cose_x509->COSE_CertHash_hashAlg_choice) {
			case COSE_CertHash_hashAlg_int_c:
				parsed_ptxt->auth_cred.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_INTEGER;
				parsed_ptxt->auth_cred.x509_hash.alg_int =
					cose_x509->COSE_CertHash_hashAlg_int;
				break;
			case COSE_CertHash_hashAlg_tstr_c:
				if (ARRAY_SIZE(parsed_ptxt->auth_cred.x509_hash
						       .alg_bstr) <
				    cose_x509->COSE_CertHash_hashAlg_tstr.len) {
					EDHOC_LOG_ERR(
						"X.509 hash alg bstr too large: %zu",
						cose_x509
							->COSE_CertHash_hashAlg_tstr
							.len);
					return EDHOC_ERROR_BUFFER_TOO_SMALL;
				}

				parsed_ptxt->auth_cred.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_BYTE_STRING;
				parsed_ptxt->auth_cred.x509_hash
					.alg_bstr_length =
					cose_x509->COSE_CertHash_hashAlg_tstr
						.len;
				memcpy(parsed_ptxt->auth_cred.x509_hash.alg_bstr,
				       cose_x509->COSE_CertHash_hashAlg_tstr
					       .value,
				       cose_x509->COSE_CertHash_hashAlg_tstr
					       .len);
				break;
			default:
				EDHOC_LOG_ERR(
					"Invalid COSE_CertHash_hashAlg choice: %d",
					cose_x509->COSE_CertHash_hashAlg_choice);
				return EDHOC_ERROR_NOT_PERMITTED;
			}

			break;
		}
	}
	}

	/* Sign_or_MAC_2 */
	parsed_ptxt->sign_or_mac =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.value;
	parsed_ptxt->sign_or_mac_len =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.len;

	/* EAD_2 if present */
	if (cbor_ptxt_2.plaintext_2_EAD_2_m_present) {
		ctx->nr_of_ead_tokens =
			cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2_count;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_label;
			ctx->ead_token[i].value =
				cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.value;
			ctx->ead_token[i].value_len =
				cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.len;
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

	if (EDHOC_TH_STATE_2 != ctx->th_state) {
		EDHOC_LOG_ERR("Invalid TH state: %d", ctx->th_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) streamed as:
	 * bstr(TH_2) || PLAINTEXT_2 || CRED_R. ctx->th holds TH_2 on input and
	 * receives TH_3 on output; the multipart update consumes it before
	 * hash_finish overwrites it. */
	const size_t th_2_len = ctx->th_len;

	uint8_t th_2_hdr[EDHOC_CBOR_BSTR_HEADER_MAX_LEN] = { 0 };

	const struct hash_segment segments[] = {
		{ th_2_hdr, edhoc_cbor_bstr_header(th_2_hdr, th_2_len) },
		{ ctx->th, th_2_len },
		{ ptxt, ptxt_len },
		{ mac_ctx->cred, mac_ctx->cred_len },
	};

	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	size_t hash_len = 0;
	const int ret = edhoc_comp_hash(ctx, segments, ARRAY_SIZE(segments),
					ctx->th, ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Hash TH_3: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->th_state = EDHOC_TH_STATE_3;
	return EDHOC_SUCCESS;
}

STATIC int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_2E != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->th_state,
			      ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	const size_t hash_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)hash_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += edhoc_cbor_int_mem_req((int32_t)hash_len);

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
	ret = ctx->itf.crypto.expand_raw(
		ctx->user_ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_2E),
		info, EDHOC_MEM_ALLOC_SIZE(info), salt, salt_len);
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand salt_3e2m: %d, %zu", ret, salt_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_grx(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx || NULL == auth_cred) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	void *grx_key_id = edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_G_RX);
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (ctx->role) {
	case EDHOC_INITIATOR:
		/* G_RX = key_agreement(ephemeral private key, R's static public
		 * key). The shared secret is produced as a handle. */
		ret = ctx->itf.crypto.key_agreement(
			ctx->user_ctx,
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
			pub_key, pub_key_len, grx_key_id);
		break;

	case EDHOC_RESPONDER:
		/* G_RX = key_agreement(R's static private key, peer's ephemeral
		 * public key G_X). */
		ret = ctx->itf.crypto.key_agreement(ctx->user_ctx,
						    auth_cred->priv_key_id,
						    ctx->peer_pub_eph_key,
						    ctx->peer_pub_eph_key_len,
						    grx_key_id);
		break;

	default:
		EDHOC_LOG_ERR("Invalid role: %d", ctx->role);
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

	if (EDHOC_SM_RECEIVED_M1 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->status,
			      ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;
	ctx->role = EDHOC_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. KEM encapsulate to the peer's G_X: produce the KEM ciphertext G_Y
	 * (sent in message 2) and the shared-secret handle. */
	ret = comp_encapsulate(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encapsulate: %d", ret);
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->pub_eph_key, ctx->pub_eph_key_len, "G_Y");

	/* 2. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_2: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->th, ctx->th_len, "TH_2");

	/* 3. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = comp_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_2e: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 4. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_cred = { 0 };
	ret = ctx->itf.cred.fetch(ctx->user_ctx, &auth_cred);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Fetch credentials: %d", ret);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 5. Compose EAD_2 if present. */
	if (NULL != ctx->itf.ead.compose &&
	    0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->itf.ead.compose(ctx->user_ctx, ctx->message,
					   ctx->ead_token,
					   ARRAY_SIZE(ctx->ead_token) - 1,
					   &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens) {
			EDHOC_LOG_ERR("EAD_2 compose failure: %d, %zu, %zu",
				      ret, ctx->nr_of_ead_tokens,
				      ARRAY_SIZE(ctx->ead_token) - 1);
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_2 compose label");

			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_2 compose value");
			}
		}
	}

	/* 6. Compute pseudorandom key (PRK_3e2m). */
	ret = comp_prk_3e2m(ctx, &auth_cred, NULL, 0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 7a. Compute required buffer length for context_2. */
	size_t mac_ctx_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &auth_cred, &mac_ctx_len);

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

	ret = edhoc_comp_mac_context(ctx, &auth_cred, mac_ctx);
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
	ret = edhoc_comp_sign_or_mac(ctx, &auth_cred, mac_ctx, mac_buf,
				     mac_length, signature,
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

	EDHOC_LOG_HEXDUMP_DBG(ctx->th, ctx->th_len, "TH_3");

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
	ctx->nr_of_ead_tokens = 0;
	ctx->itf.platform.zeroize(ctx->ead_token, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_WAIT_M3;
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

	if (EDHOC_SM_WAIT_M2 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->status,
			      ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;
	ctx->role = EDHOC_INITIATOR;

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
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;
	}

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_2: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->th, ctx->th_len, "TH_2");

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

	switch (ctx->peer_cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		EDHOC_LOG_HEXDUMP_DBG((const uint8_t *)&ctx->peer_cid.int_value,
				      sizeof(ctx->peer_cid.int_value), "C_R");
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		EDHOC_LOG_HEXDUMP_DBG(ctx->peer_cid.bstr_value,
				      ctx->peer_cid.bstr_length, "C_R");
		break;

	default:
		EDHOC_LOG_ERR("Invalid peer CID type: %d",
			      ctx->peer_cid.encode_type);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* 9. Process EAD if present. */
	if (NULL != ctx->itf.ead.process &&
	    0 != ARRAY_SIZE(ctx->ead_token) - 1 && 0 != ctx->nr_of_ead_tokens) {
		ret = ctx->itf.ead.process(ctx->user_ctx, ctx->message,
					   ctx->ead_token,
					   ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("EAD_2 process: %d", ret);
			EDHOC_MEM_FREE(ciphertext_2);
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_2 process label");

			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_2 process value");
			}
		}
	}

	/* 10. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;

	ret = ctx->itf.cred.verify(ctx->user_ctx, &parsed_ptxt.auth_cred,
				   &pub_key, &pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Credentials verification: %d", ret);
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 11. Compute pseudorandom key (PRK_3e2m). */
	ret = comp_prk_3e2m(ctx, &parsed_ptxt.auth_cred, pub_key, pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 12. Compute required buffer length for context_2. */
	size_t mac_context_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &parsed_ptxt.auth_cred,
					    &mac_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context length: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_INVALID_MAC_2;
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

	ret = edhoc_comp_mac_context(ctx, &parsed_ptxt.auth_cred, mac_ctx);
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
	ret = edhoc_verify_sign_or_mac(ctx, mac_ctx, pub_key, pub_key_len,
				       parsed_ptxt.sign_or_mac,
				       parsed_ptxt.sign_or_mac_len, mac_buf,
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

	EDHOC_LOG_HEXDUMP_DBG(ctx->th, ctx->th_len, "TH_3");
	EDHOC_LOG_INF("Process msg2 end");

	/* 17. Release the message-2 scoped secrets (PRK_3e2m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 2 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 18. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	ctx->itf.platform.zeroize(ctx->ead_token, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
