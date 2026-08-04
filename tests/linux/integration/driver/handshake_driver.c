/**
 * \file    handshake_driver.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the parametrized EDHOC handshake test driver.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Handshake driver headers: */
#include "handshake_driver.h"
#include "handshake_credentials.h"
#include "handshake_ead.h"

/* EDHOC public headers: */
#include <edhoc/edhoc.h>

/* Unity headers: */
#include <unity.h>

/* Standard library headers: */
#include <string.h>

/* Module defines ---------------------------------------------------------- */

/** \brief Bytes derived through the generic exporter to compare both peers. */
#define HS_EXPORT_SECRET_LENGTH ((size_t)16)

/** \brief expand_raw output length used to prove two key slots match. */
#define HS_SLOT_CHECK_LENGTH ((size_t)32)

/** \brief Plaintext length for the cross-peer AEAD key-agreement proof. */
#define HS_AEAD_PLAINTEXT_LENGTH ((size_t)16)

/** \brief Largest AEAD nonce across the supported suites. */
#define HS_AEAD_NONCE_MAX ((size_t)16)

/** \brief Largest AEAD authentication tag across the supported suites. */
#define HS_AEAD_TAG_MAX ((size_t)16)

/** \brief Ciphertext buffer: plaintext plus the largest AEAD tag. */
#define HS_AEAD_CIPHERTEXT_MAX (HS_AEAD_PLAINTEXT_LENGTH + HS_AEAD_TAG_MAX)

/* Types and type definitions ---------------------------------------------- */

/** \brief Which OSCORE export API a compare pass exercises. */
enum hs_oscore_export {
	/** Master secret returned as raw bytes (\c edhoc_export_oscore_context_raw). */
	HS_OSCORE_RAW,
	/** Master secret returned as a key handle (\c edhoc_export_oscore_context). */
	HS_OSCORE_HANDLE,
};

/* Static variables and constants ------------------------------------------ */

/* The generic callbacks are identical for every scenario; the per-endpoint
 * data travels through the bound user context (struct handshake_endpoint). */
static const struct edhoc_credentials hs_credentials = {
	.select_local = hs_cred_select_local,
	.authenticate_peer = hs_cred_authenticate_peer,
};

static const struct edhoc_ead hs_ead_interface = {
	.compose = hs_ead_compose,
	.process = hs_ead_process,
};

/* Fixed application context for the EDHOC key update (both peers must rotate
 * PRK_out with the same context, so a fixed vector keeps the test hermetic). */
static const uint8_t hs_key_update_context[HS_KEY_UPDATE_CONTEXT_LENGTH] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

/* Fixed non-zero AEAD nonce for the cross-peer key-agreement proof. */
static const uint8_t hs_aead_nonce[HS_AEAD_NONCE_MAX] = {
	0xa5, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
};

/* Fixed plaintext round-tripped through both peers' exported AEAD keys. */
static const uint8_t hs_aead_plaintext[HS_AEAD_PLAINTEXT_LENGTH] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

/* Fixed associated data for the cross-peer key-agreement proof. */
static const uint8_t hs_aead_associated_data[] = { 'h', 's', '-', 'a',
						   'e', 'a', 'd' };

/* Static function declarations -------------------------------------------- */

/** \brief Configure one fresh context for its endpoint in the scenario. */
static void hs_setup_context(struct edhoc_context *ctx,
			     const struct handshake_scenario *scenario,
			     const struct handshake_endpoint *endpoint);

/** \brief Assert the context recorded no EDHOC error for the session. */
static void hs_assert_no_error(const struct edhoc_context *ctx);

/** \brief Assert the peer connection id learned from the wire is as expected. */
static void hs_assert_peer_connection_id(const struct edhoc_context *ctx,
					 const struct edhoc_buffer *expected);

static void hs_assert_peers_share_slot(const struct edhoc_crypto *crypto,
				       const struct edhoc_context *lhs,
				       const struct edhoc_context *rhs,
				       enum edhoc_key_slot_id slot);

/** \brief Prove two AEAD key handles hold the same key by cross en/decryption. */
static void
hs_assert_aead_keys_match(const struct edhoc_crypto *crypto,
			  const struct edhoc_cipher_suite *cipher_suite,
			  const void *key_id_lhs, const void *key_id_rhs);

/** \brief Export the OSCORE Security Context on both peers and prove agreement. */
static void hs_export_oscore_and_compare(
	struct edhoc_context *init_ctx, struct edhoc_context *resp_ctx,
	const struct edhoc_cipher_suite *cipher_suite,
	const struct edhoc_crypto *crypto, enum hs_oscore_export kind);

/** \brief Run the EDHOC key update on both peers (opens a fresh export window). */
static void hs_key_update(struct edhoc_context *init_ctx,
			  struct edhoc_context *resp_ctx);

/** \brief Exercise the generic application exporter and prove peer agreement. */
static void
hs_export_generic_and_compare(struct edhoc_context *init_ctx,
			      struct edhoc_context *resp_ctx,
			      const struct edhoc_cipher_suite *cipher_suite,
			      const struct edhoc_crypto *crypto);

/* Static function definitions --------------------------------------------- */

static void hs_setup_context(struct edhoc_context *ctx,
			     const struct handshake_scenario *scenario,
			     const struct handshake_endpoint *endpoint)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_crypto *crypto = edhoc_cipher_suite_get_crypto(
		(enum edhoc_cipher_suite_id)scenario->cipher_suites[0].value);
	TEST_ASSERT_NOT_NULL(crypto);

	ret = edhoc_context_init(ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(ctx, scenario->methods,
				scenario->methods_count);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(ctx, scenario->cipher_suites,
				      scenario->cipher_suites_count);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(ctx, &endpoint->connection_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The endpoint is the single user context every callback receives. */
	ret = edhoc_set_user_context(ctx, (void *)endpoint);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	if (NULL != endpoint->ead) {
		ret = edhoc_bind_ead(ctx, &hs_ead_interface);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}

	ret = edhoc_bind_crypto(ctx, crypto);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(ctx, scenario->platform);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(ctx, &hs_credentials);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

static void hs_assert_no_error(const struct edhoc_context *ctx)
{
	enum edhoc_error_code error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

	const int ret = edhoc_error_get_code(ctx, &error_code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code);
}

static void hs_assert_peer_connection_id(const struct edhoc_context *ctx,
					 const struct edhoc_buffer *expected)
{
	const struct connection_id *received =
		&ctx->negotiation.peer_connection_id;

	TEST_ASSERT_EQUAL_size_t(expected->length, received->length);

	/* Unity refuses an array comparison of zero elements. */
	if (0 != expected->length) {
		TEST_ASSERT_EQUAL_UINT8_ARRAY(expected->value, received->value,
					      expected->length);
	}
}

static void hs_assert_peers_share_slot(const struct edhoc_crypto *crypto,
				       const struct edhoc_context *lhs,
				       const struct edhoc_context *rhs,
				       enum edhoc_key_slot_id slot)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	static const uint8_t info[] = { 'k', 'e', 'y', '-', 'c',
					'h', 'e', 'c', 'k' };
	uint8_t lhs_output[HS_SLOT_CHECK_LENGTH] = { 0 };
	uint8_t rhs_output[HS_SLOT_CHECK_LENGTH] = { 0 };

	TEST_ASSERT_TRUE(lhs->key_slots[slot].present);
	TEST_ASSERT_TRUE(rhs->key_slots[slot].present);

	ret = crypto->expand_raw(NULL, lhs->key_slots[slot].key_id, info,
				 sizeof(info), lhs_output, sizeof(lhs_output));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->expand_raw(NULL, rhs->key_slots[slot].key_id, info,
				 sizeof(info), rhs_output, sizeof(rhs_output));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(lhs_output, rhs_output,
				      sizeof(lhs_output));
}

static void
hs_assert_aead_keys_match(const struct edhoc_crypto *crypto,
			  const struct edhoc_cipher_suite *cipher_suite,
			  const void *key_id_lhs, const void *key_id_rhs)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* One peer encrypts, the other must be able to decrypt to the original
	 * plaintext; repeated in both directions. This proves the two handles
	 * hold the same AEAD key, rather than merely that an export succeeded. */
	for (size_t direction = 0; direction < 2; ++direction) {
		const void *encrypt_key_id = (0 == direction) ? key_id_lhs :
								key_id_rhs;
		const void *decrypt_key_id = (0 == direction) ? key_id_rhs :
								key_id_lhs;

		uint8_t ciphertext[HS_AEAD_CIPHERTEXT_MAX] = { 0 };
		size_t ciphertext_length = 0;

		ret = crypto->aead_encrypt(
			NULL, encrypt_key_id, hs_aead_nonce,
			cipher_suite->aead_iv_length, hs_aead_associated_data,
			sizeof(hs_aead_associated_data), hs_aead_plaintext,
			sizeof(hs_aead_plaintext), ciphertext,
			sizeof(ciphertext), &ciphertext_length);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t recovered[HS_AEAD_PLAINTEXT_LENGTH] = { 0 };
		size_t recovered_length = 0;

		ret = crypto->aead_decrypt(NULL, decrypt_key_id, hs_aead_nonce,
					   cipher_suite->aead_iv_length,
					   hs_aead_associated_data,
					   sizeof(hs_aead_associated_data),
					   ciphertext, ciphertext_length,
					   recovered, sizeof(recovered),
					   &recovered_length);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		TEST_ASSERT_EQUAL(sizeof(hs_aead_plaintext), recovered_length);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(hs_aead_plaintext, recovered,
					      sizeof(hs_aead_plaintext));
	}
}

static void hs_export_oscore_and_compare(
	struct edhoc_context *init_ctx, struct edhoc_context *resp_ctx,
	const struct edhoc_cipher_suite *cipher_suite,
	const struct edhoc_crypto *crypto, enum hs_oscore_export kind)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t init_secret[HS_OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t resp_secret[HS_OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t init_secret_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	uint8_t resp_secret_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	uint8_t init_salt[HS_OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t init_sender_id[HS_OSCORE_ID_MAX] = { 0 };
	uint8_t init_recipient_id[HS_OSCORE_ID_MAX] = { 0 };
	size_t init_sender_id_length = 0;
	size_t init_recipient_id_length = 0;

	uint8_t resp_salt[HS_OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t resp_sender_id[HS_OSCORE_ID_MAX] = { 0 };
	uint8_t resp_recipient_id[HS_OSCORE_ID_MAX] = { 0 };
	size_t resp_sender_id_length = 0;
	size_t resp_recipient_id_length = 0;

	switch (kind) {
	case HS_OSCORE_RAW:
		ret = edhoc_export_oscore_context_raw(
			init_ctx, init_secret, sizeof(init_secret), init_salt,
			sizeof(init_salt), init_sender_id,
			sizeof(init_sender_id), &init_sender_id_length,
			init_recipient_id, sizeof(init_recipient_id),
			&init_recipient_id_length);
		break;

	case HS_OSCORE_HANDLE:
		ret = edhoc_export_oscore_context(
			init_ctx, init_secret_id, init_salt, sizeof(init_salt),
			init_sender_id, sizeof(init_sender_id),
			&init_sender_id_length, init_recipient_id,
			sizeof(init_recipient_id), &init_recipient_id_length);
		break;
	}

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->state.prk_state);

	switch (kind) {
	case HS_OSCORE_RAW:
		ret = edhoc_export_oscore_context_raw(
			resp_ctx, resp_secret, sizeof(resp_secret), resp_salt,
			sizeof(resp_salt), resp_sender_id,
			sizeof(resp_sender_id), &resp_sender_id_length,
			resp_recipient_id, sizeof(resp_recipient_id),
			&resp_recipient_id_length);
		break;

	case HS_OSCORE_HANDLE:
		ret = edhoc_export_oscore_context(
			resp_ctx, resp_secret_id, resp_salt, sizeof(resp_salt),
			resp_sender_id, sizeof(resp_sender_id),
			&resp_sender_id_length, resp_recipient_id,
			sizeof(resp_recipient_id), &resp_recipient_id_length);
		break;
	}
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->state.prk_state);

	/* Mirrored master salt and sender / recipient identifiers. */
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_salt, resp_salt,
				      HS_OSCORE_MASTER_SALT_LENGTH);
	TEST_ASSERT_EQUAL(init_sender_id_length, resp_recipient_id_length);
	TEST_ASSERT_EQUAL(init_recipient_id_length, resp_sender_id_length);

	/* An empty connection identifier gives an empty OSCORE identifier
	 * (RFC 9528: 3.3.3), which Unity refuses to compare. */
	if (0 != init_sender_id_length) {
		TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
					      init_sender_id_length);
	}

	if (0 != resp_sender_id_length) {
		TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
					      resp_sender_id_length);
	}

	switch (kind) {
	case HS_OSCORE_RAW:
		/* Raw bytes: the master secret compares directly. */
		TEST_ASSERT_EQUAL_UINT8_ARRAY(init_secret, resp_secret,
					      HS_OSCORE_MASTER_SECRET_LENGTH);
		break;

	case HS_OSCORE_HANDLE:
		/* Opaque handle: prove agreement by cross en/decryption, then
		 * release the caller-owned key handles. */
		hs_assert_aead_keys_match(crypto, cipher_suite, init_secret_id,
					  resp_secret_id);

		ret = crypto->destroy_key(NULL, init_secret_id);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = crypto->destroy_key(NULL, resp_secret_id);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		break;
	}
}

static void hs_key_update(struct edhoc_context *init_ctx,
			  struct edhoc_context *resp_ctx)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	ret = edhoc_export_key_update(init_ctx, hs_key_update_context,
				      sizeof(hs_key_update_context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->state.prk_state);

	ret = edhoc_export_key_update(resp_ctx, hs_key_update_context,
				      sizeof(hs_key_update_context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->state.prk_state);
}

static void
hs_export_generic_and_compare(struct edhoc_context *init_ctx,
			      struct edhoc_context *resp_ctx,
			      const struct edhoc_cipher_suite *cipher_suite,
			      const struct edhoc_crypto *crypto)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	const size_t label = EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MINIMUM;

	/* Raw bytes: both peers must derive the same secret. */
	uint8_t init_secret[HS_EXPORT_SECRET_LENGTH] = { 0 };
	uint8_t resp_secret[HS_EXPORT_SECRET_LENGTH] = { 0 };

	ret = edhoc_export_raw(init_ctx, label, NULL, 0, init_secret,
			       sizeof(init_secret));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_raw(resp_ctx, label, NULL, 0, resp_secret,
			       sizeof(resp_secret));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_secret, resp_secret,
				      HS_EXPORT_SECRET_LENGTH);

	/* Key handle (AEAD usage): prove both peers derive the same working key
	 * by cross en/decryption, then release the handles. */
	uint8_t init_key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	uint8_t resp_key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	ret = edhoc_export(init_ctx, label, NULL, 0, EDHOC_KEY_USAGE_AEAD,
			   init_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export(resp_ctx, label, NULL, 0, EDHOC_KEY_USAGE_AEAD,
			   resp_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	hs_assert_aead_keys_match(crypto, cipher_suite, init_key_id,
				  resp_key_id);

	ret = crypto->destroy_key(NULL, init_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = crypto->destroy_key(NULL, resp_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

/* Module interface function definitions ----------------------------------- */

void run_handshake(const struct handshake_scenario *scenario)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_crypto *crypto = edhoc_cipher_suite_get_crypto(
		(enum edhoc_cipher_suite_id)scenario->cipher_suites[0].value);
	const struct edhoc_cipher_suite *cipher_suite =
		&scenario->cipher_suites[0];
	TEST_ASSERT_NOT_NULL(crypto);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	/* The credential callbacks assert the call context they observe, which
	 * only the driver knows in full. */
	struct handshake_endpoint init_endpoint = scenario->init;
	struct handshake_endpoint resp_endpoint = scenario->resp;
	init_endpoint.expected_cipher_suite = cipher_suite->value;
	resp_endpoint.expected_cipher_suite = cipher_suite->value;

	hs_setup_context(&init_ctx, scenario, &init_endpoint);
	hs_setup_context(&resp_ctx, scenario, &resp_endpoint);

	uint8_t message[HS_MESSAGE_BUFFER_SIZE] = { 0 };
	size_t message_length = 0;

	/* --- Message 1 (Initiator -> Responder) --- */
	ret = edhoc_message_1_compose(&init_ctx, message, sizeof(message),
				      &message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx.state.machine);
	TEST_ASSERT_EQUAL(false, init_ctx.is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx.state.prk_state);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx.state.th.stage);
	hs_assert_no_error(&init_ctx);

	ret = edhoc_message_1_process(&resp_ctx, message, message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx.state.machine);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx.state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx.state.prk_state);
	hs_assert_no_error(&resp_ctx);
	hs_assert_peer_connection_id(&resp_ctx, &scenario->init.connection_id);

	/* --- Message 2 (Responder -> Initiator) --- */
	memset(message, 0, sizeof(message));
	ret = edhoc_message_2_compose(&resp_ctx, message, sizeof(message),
				      &message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx.state.machine);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx.state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx.state.prk_state);
	hs_assert_no_error(&resp_ctx);

	ret = edhoc_message_2_process(&init_ctx, message, message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx.state.machine);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx.state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx.state.prk_state);
	hs_assert_no_error(&init_ctx);
	hs_assert_peer_connection_id(&init_ctx, &scenario->resp.connection_id);

	/* Both peers derived the same PRK_3e2m (ephemeral key exchange). */
	hs_assert_peers_share_slot(crypto, &init_ctx, &resp_ctx,
				   EDHOC_KEY_SLOT_PRK_3E2M);

	/* --- Message 3 (Initiator -> Responder) --- */
	memset(message, 0, sizeof(message));
	ret = edhoc_message_3_compose(&init_ctx, message, sizeof(message),
				      &message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx.state.machine);
	TEST_ASSERT_EQUAL(true, init_ctx.is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx.state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx.state.prk_state);
	hs_assert_no_error(&init_ctx);

	ret = edhoc_message_3_process(&resp_ctx, message, message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx.state.machine);
	TEST_ASSERT_EQUAL(true, resp_ctx.is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx.state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx.state.prk_state);
	hs_assert_no_error(&resp_ctx);

	/* Both peers derived the same PRK_4e3m (message 3/4 auth key). */
	hs_assert_peers_share_slot(crypto, &init_ctx, &resp_ctx,
				   EDHOC_KEY_SLOT_PRK_4E3M);

	/* --- Message 4 (Responder -> Initiator) --- */
	memset(message, 0, sizeof(message));
	ret = edhoc_message_4_compose(&resp_ctx, message, sizeof(message),
				      &message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx.state.machine);
	TEST_ASSERT_EQUAL(true, resp_ctx.is_oscore_export_allowed);
	hs_assert_no_error(&resp_ctx);

	ret = edhoc_message_4_process(&init_ctx, message, message_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx.state.machine);
	TEST_ASSERT_EQUAL(true, init_ctx.is_oscore_export_allowed);
	hs_assert_no_error(&init_ctx);

	/* --- OSCORE Security Context (raw bytes) must agree --- */
	hs_export_oscore_and_compare(&init_ctx, &resp_ctx, cipher_suite, crypto,
				     HS_OSCORE_RAW);
	hs_assert_peers_share_slot(crypto, &init_ctx, &resp_ctx,
				   EDHOC_KEY_SLOT_PRK_OUT);

	/* --- Key update, then OSCORE re-export (key handle) must agree --- */
	hs_key_update(&init_ctx, &resp_ctx);
	hs_assert_peers_share_slot(crypto, &init_ctx, &resp_ctx,
				   EDHOC_KEY_SLOT_PRK_OUT);
	hs_export_oscore_and_compare(&init_ctx, &resp_ctx, cipher_suite, crypto,
				     HS_OSCORE_HANDLE);

	/* --- Generic application exporter must agree --- */
	hs_export_generic_and_compare(&init_ctx, &resp_ctx, cipher_suite,
				      crypto);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}
