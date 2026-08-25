/**
 * \file    test_draft_edhoc_psk_08.c
 * \author  Kamil Kielbasa
 * \brief   Module tests according to EDHOC-PSK
 *          (draft-ietf-lake-edhoc-psk-08), Appendix B.
 *
 *          Both peers authenticate with a pre-shared key (METHOD = 4) over
 *          cipher suite 2. The PSK, CRED_I and CRED_R are reached through the
 *          existing authentication credentials interface: the Initiator selects
 *          them with \c select_local, the Responder resolves them from the
 *          received ID_CRED_PSK with \c authenticate_peer. Each peer binds only
 *          the callback its role uses; the other stays NULL.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Test support headers: */
#include "test_platform.h"
#include "test_draft_edhoc_psk_08_support.h"
#include "edhoc_context_internal.h"
#include "test_vector_draft_edhoc_psk_08.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Authentication credentials fetch callback for initiator.
 */
static int
auth_cred_select_local_init(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_credential_selected *selected);

/**
 * \brief Authentication credentials authenticate peer callback for responder.
 */
static int auth_cred_authenticate_peer_resp(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted);

/**
 * \brief Authentication credentials fetch callback for responder; EDHOC-PSK
 *        never calls it.
 */
static int
auth_cred_select_local_resp_unused(void *user_ctx,
				   const struct edhoc_call_context *call_ctx,
				   struct edhoc_credential_selected *selected);

/**
 * \brief Authentication credentials authenticate peer callback for initiator;
 *        EDHOC-PSK never calls it.
 */
static int auth_cred_authenticate_peer_init_unused(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted);

/* Static variables and constants ------------------------------------------ */

static int ret = EDHOC_ERROR_GENERIC_ERROR;
static enum edhoc_error_code error_code_recv =
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

static struct edhoc_context edhoc_initiator_context = { 0 };
static struct edhoc_context *init_ctx = &edhoc_initiator_context;

static struct edhoc_context edhoc_responder_context = { 0 };
static struct edhoc_context *resp_ctx = &edhoc_responder_context;

static struct edhoc_crypto edhoc_crypto_mocked_init;
static struct edhoc_crypto edhoc_crypto_mocked_resp;

/* EDHOC-PSK calls exactly one credentials callback per role. */
static const struct edhoc_credentials edhoc_auth_cred_mocked_init = {
	.select_local = auth_cred_select_local_init,
	.authenticate_peer = auth_cred_authenticate_peer_init_unused,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp = {
	.select_local = auth_cred_select_local_resp_unused,
	.authenticate_peer = auth_cred_authenticate_peer_resp,
};

/* Static function definitions --------------------------------------------- */

/* Initiator ephemeral: inject the draft's fixed X / G_X. */
static int mocked_generate_key_pair_init(void *user_ctx, void *decaps_key_id,
					 uint8_t *encaps_key,
					 size_t encaps_key_size,
					 size_t *encaps_key_len)
{
	(void)user_ctx;

	TEST_ASSERT_NOT_NULL(decaps_key_id);
	TEST_ASSERT_NOT_NULL(encaps_key);
	TEST_ASSERT_TRUE(encaps_key_size >= ARRAY_SIZE(G_X));
	TEST_ASSERT_NOT_NULL(encaps_key_len);

	const psa_key_id_t kid = tv_import_p256(X, ARRAY_SIZE(X));

	memcpy(decaps_key_id, &kid, sizeof(kid));

	memcpy(encaps_key, G_X, ARRAY_SIZE(G_X));
	*encaps_key_len = ARRAY_SIZE(G_X);

	return EDHOC_SUCCESS;
}

/* Responder ephemeral: inject the draft's fixed Y / G_Y and hand back G_XY. */
static int mocked_encapsulate_resp(void *user_ctx, const uint8_t *encaps_key,
				   size_t encaps_key_len, void *decaps_key_id,
				   void *shared_secret_key_id,
				   uint8_t *ciphertext, size_t ciphertext_size,
				   size_t *ciphertext_len)
{
	(void)user_ctx;

	TEST_ASSERT_NOT_NULL(encaps_key);
	TEST_ASSERT_NOT_EQUAL(0, encaps_key_len);
	TEST_ASSERT_NOT_NULL(decaps_key_id);
	TEST_ASSERT_NOT_NULL(shared_secret_key_id);
	TEST_ASSERT_NOT_NULL(ciphertext);
	TEST_ASSERT_TRUE(ciphertext_size >= ARRAY_SIZE(G_Y));
	TEST_ASSERT_NOT_NULL(ciphertext_len);

	/* The library must hand us the initiator's ephemeral public key G_X. */
	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), encaps_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, encaps_key, encaps_key_len);

	const psa_key_id_t eph = tv_import_p256(Y, ARRAY_SIZE(Y));

	/* Cross-check G_XY = ECDH(Y, G_X). EDHOC transmits only the 32-byte
	 * x-coordinate, so decompress G_X to a full SECP_R1 point first. */
	uint8_t g_x_point[TEST_P256_UNCOMPRESSED_LEN] = { 0 };
	size_t g_x_point_len = 0;
	tv_p256_uncompress(encaps_key, encaps_key_len, g_x_point,
			   sizeof(g_x_point), &g_x_point_len);
	tv_check_shared_secret(eph, g_x_point, g_x_point_len, G_XY,
			       ARRAY_SIZE(G_XY));

	memcpy(ciphertext, G_Y, ARRAY_SIZE(G_Y));
	*ciphertext_len = ARRAY_SIZE(G_Y);

	const psa_key_id_t shared = tv_import_derive(G_XY, ARRAY_SIZE(G_XY));

	memcpy(shared_secret_key_id, &shared, sizeof(shared));
	memcpy(decaps_key_id, &eph, sizeof(eph));

	return EDHOC_SUCCESS;
}

/* Initiator side of G_XY: pin the received ciphertext to the draft's G_Y,
 * verify G_XY = ECDH(X, G_Y), and hand back the draft's G_XY. */
static int mocked_decapsulate_init(void *user_ctx, const void *decaps_key_id,
				   const uint8_t *ciphertext,
				   size_t ciphertext_len,
				   void *shared_secret_key_id)
{
	(void)user_ctx;

	TEST_ASSERT_NOT_NULL(decaps_key_id);
	TEST_ASSERT_NOT_NULL(ciphertext);
	TEST_ASSERT_NOT_NULL(shared_secret_key_id);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_Y), ciphertext_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_Y, ciphertext, ciphertext_len);

	psa_key_id_t eph = PSA_KEY_ID_NULL;
	memcpy(&eph, decaps_key_id, sizeof(eph));

	uint8_t g_y_point[TEST_P256_UNCOMPRESSED_LEN] = { 0 };
	size_t g_y_point_len = 0;
	tv_p256_uncompress(ciphertext, ciphertext_len, g_y_point,
			   sizeof(g_y_point), &g_y_point_len);
	tv_check_shared_secret(eph, g_y_point, g_y_point_len, G_XY,
			       ARRAY_SIZE(G_XY));

	const psa_key_id_t shared = tv_import_derive(G_XY, ARRAY_SIZE(G_XY));

	memcpy(shared_secret_key_id, &shared, sizeof(shared));

	return EDHOC_SUCCESS;
}

/* Import the PSK as the derive key the EDHOC_Extract of PRK_4e3m consumes. */
static int import_psk(uint8_t *key_id, size_t key_id_size)
{
	TEST_ASSERT_NOT_NULL(key_id);

	const psa_key_id_t kid = tv_import_derive(PSK, ARRAY_SIZE(PSK));

	TEST_ASSERT_TRUE(key_id_size >= sizeof(kid));
	memcpy(key_id, &kid, sizeof(kid));

	return EDHOC_SUCCESS;
}

static int
auth_cred_select_local_init(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_credential_selected *selected)
{
	(void)user_ctx;

	if (NULL == call_ctx || NULL == selected) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* Draft: 3.2 - the credential fields appear first in message 3. */
	TEST_ASSERT_EQUAL(EDHOC_ROLE_INITIATOR, call_ctx->role);
	TEST_ASSERT_EQUAL(EDHOC_METHOD_4, call_ctx->method);
	TEST_ASSERT_EQUAL(EDHOC_MESSAGE_3, call_ctx->message);

	selected->psk.label = EDHOC_COSE_HEADER_KID;
	selected->psk.kid.identifier.value = ID_CRED_PSK;
	selected->psk.kid.identifier.length = ARRAY_SIZE(ID_CRED_PSK);
	selected->psk.cred_i.value = CRED_I;
	selected->psk.cred_i.length = ARRAY_SIZE(CRED_I);
	selected->psk.cred_r.value = CRED_R;
	selected->psk.cred_r.length = ARRAY_SIZE(CRED_R);
	selected->psk.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int res = import_psk(selected->psk.psk_key_id,
				   ARRAY_SIZE(selected->psk.psk_key_id));

	if (EDHOC_SUCCESS != res) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int auth_cred_authenticate_peer_resp(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	(void)user_ctx;

	if (NULL == call_ctx || NULL == received || NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	TEST_ASSERT_EQUAL(EDHOC_ROLE_RESPONDER, call_ctx->role);
	TEST_ASSERT_EQUAL(EDHOC_METHOD_4, call_ctx->method);
	TEST_ASSERT_EQUAL(EDHOC_MESSAGE_3, call_ctx->message);

	if (EDHOC_COSE_HEADER_KID != received->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* Draft: 3.1 - ID_CRED_PSK is what resolves the PSK and both CREDs. */
	if (ARRAY_SIZE(ID_CRED_PSK) != received->kid.identifier.length ||
	    0 != memcmp(ID_CRED_PSK, received->kid.identifier.value,
			received->kid.identifier.length)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	trusted->psk.cred_i.value = CRED_I;
	trusted->psk.cred_i.length = ARRAY_SIZE(CRED_I);
	trusted->psk.cred_r.value = CRED_R;
	trusted->psk.cred_r.length = ARRAY_SIZE(CRED_R);
	trusted->psk.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int res = import_psk(trusted->psk.psk_key_id,
				   ARRAY_SIZE(trusted->psk.psk_key_id));

	if (EDHOC_SUCCESS != res) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int
auth_cred_select_local_resp_unused(void *user_ctx,
				   const struct edhoc_call_context *call_ctx,
				   struct edhoc_credential_selected *selected)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)selected;

	return EDHOC_ERROR_NOT_PERMITTED;
}

static int auth_cred_authenticate_peer_init_unused(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)received;
	(void)trusted;

	return EDHOC_ERROR_NOT_PERMITTED;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(draft_edhoc_psk_08);
TEST_SETUP(draft_edhoc_psk_08)
{
	ret = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	const struct edhoc_cipher_suite *const suite =
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2);
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *const crypto =
		edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2);
	TEST_ASSERT_NOT_NULL(crypto);

	edhoc_crypto_mocked_init = *crypto;
	edhoc_crypto_mocked_init.generate_key_pair =
		mocked_generate_key_pair_init;
	edhoc_crypto_mocked_init.decapsulate = mocked_decapsulate_init;

	edhoc_crypto_mocked_resp = *crypto;
	edhoc_crypto_mocked_resp.encapsulate = mocked_encapsulate_resp;

	const enum edhoc_method methods[] = { METHOD };

	const struct edhoc_buffer init_cid = { .value = C_I,
					       .length = ARRAY_SIZE(C_I) };
	const struct edhoc_buffer resp_cid = { .value = C_R,
					       .length = ARRAY_SIZE(C_R) };

	ret = edhoc_context_init(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(init_ctx, suite, 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(init_ctx, &init_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(init_ctx, &edhoc_crypto_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(init_ctx, &edhoc_auth_cred_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_init(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(resp_ctx, suite, 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(resp_ctx, &resp_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(resp_ctx, &edhoc_crypto_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(resp_ctx, &edhoc_auth_cred_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_TEAR_DOWN(draft_edhoc_psk_08)
{
	ret = edhoc_context_deinit(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mbedtls_psa_crypto_free();
}

TEST(draft_edhoc_psk_08, message_1_compose)
{
	size_t msg_1_len = 0;
	uint8_t msg_1[ARRAY_SIZE(message_1)] = { 0 };

	ret = edhoc_message_1_compose(init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_1), msg_1_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_1, msg_1, msg_1_len);

	TEST_ASSERT_EQUAL(METHOD, init_ctx->negotiation.selected_method);
	TEST_ASSERT_EQUAL(EDHOC_CIPHER_SUITE_2,
			  edhoc_selected_cipher_suite(init_ctx)->value);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), init_ctx->ephemeral.own.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, init_ctx->ephemeral.own.value,
				      init_ctx->ephemeral.own.length);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(H_message_1), init_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(H_message_1, init_ctx->state.th.value,
				      init_ctx->state.th.length);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx->state.prk_state);
}

TEST(draft_edhoc_psk_08, message_1_process)
{
	ret = edhoc_message_1_process(resp_ctx, message_1,
				      ARRAY_SIZE(message_1));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(METHOD, resp_ctx->negotiation.selected_method);
	TEST_ASSERT_EQUAL(EDHOC_CIPHER_SUITE_2,
			  edhoc_selected_cipher_suite(resp_ctx)->value);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(H_message_1), resp_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(H_message_1, resp_ctx->state.th.value,
				      resp_ctx->state.th.length);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx->state.prk_state);

	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(C_I),
		resp_ctx->negotiation.peer_connection_id.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		C_I, resp_ctx->negotiation.peer_connection_id.value,
		ARRAY_SIZE(C_I));

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), resp_ctx->ephemeral.peer.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, resp_ctx->ephemeral.peer.value,
				      resp_ctx->ephemeral.peer.length);
}

TEST(draft_edhoc_psk_08, message_2_compose)
{
	/* Required injections. */
	resp_ctx->state.machine = EDHOC_SM_RECEIVED_M1;
	resp_ctx->negotiation.selected_method = METHOD;

	resp_ctx->state.th.stage = EDHOC_TH_STATE_1;
	resp_ctx->state.th.length = ARRAY_SIZE(H_message_1);
	memcpy(resp_ctx->state.th.value, H_message_1, ARRAY_SIZE(H_message_1));

	resp_ctx->ephemeral.peer.length = ARRAY_SIZE(G_X);
	memcpy(resp_ctx->ephemeral.peer.value, G_X, ARRAY_SIZE(G_X));

	memcpy(resp_ctx->negotiation.peer_connection_id.value, C_I,
	       ARRAY_SIZE(C_I));
	resp_ctx->negotiation.peer_connection_id.length = ARRAY_SIZE(C_I);

	size_t msg_2_len = 0;
	uint8_t msg_2[ARRAY_SIZE(message_2)] = { 0 };

	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(msg_2),
				      &msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_2), msg_2_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_2, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_Y), resp_ctx->ephemeral.own.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_Y, resp_ctx->ephemeral.own.value,
				      resp_ctx->ephemeral.own.length);

	/* Draft: 4 - TH_3 = H( TH_2, PLAINTEXT_2A ), with no CRED_R. */
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_3), resp_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_3, resp_ctx->state.th.value,
				      resp_ctx->state.th.length);

	/* Draft: 4 - PRK_3e2m = PRK_2e, so the handle moves rather than being
	 * derived anew. */
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->state.prk_state);
	TEST_ASSERT_FALSE(resp_ctx->key_slots[EDHOC_KEY_SLOT_PRK_2E].present);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));
}

TEST(draft_edhoc_psk_08, message_2_process)
{
	/* Required injections. */
	init_ctx->state.machine = EDHOC_SM_WAIT_M2;
	init_ctx->negotiation.selected_method = METHOD;

	init_ctx->state.th.stage = EDHOC_TH_STATE_1;
	init_ctx->state.th.length = ARRAY_SIZE(H_message_1);
	memcpy(init_ctx->state.th.value, H_message_1, ARRAY_SIZE(H_message_1));

	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_EPHEMERAL,
		       tv_import_p256(X, ARRAY_SIZE(X)));

	ret = edhoc_message_2_process(init_ctx, message_2,
				      ARRAY_SIZE(message_2));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_3), init_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_3, init_ctx->state.th.value,
				      init_ctx->state.th.length);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->state.prk_state);
	TEST_ASSERT_FALSE(init_ctx->key_slots[EDHOC_KEY_SLOT_PRK_2E].present);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, init_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_Y), init_ctx->ephemeral.peer.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_Y, init_ctx->ephemeral.peer.value,
				      init_ctx->ephemeral.peer.length);

	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(C_R),
		init_ctx->negotiation.peer_connection_id.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		C_R, init_ctx->negotiation.peer_connection_id.value,
		ARRAY_SIZE(C_R));
}

TEST(draft_edhoc_psk_08, message_3_compose)
{
	/* Required injections. */
	init_ctx->state.machine = EDHOC_SM_VERIFIED_M2;
	init_ctx->negotiation.selected_method = METHOD;

	init_ctx->state.th.stage = EDHOC_TH_STATE_3;
	init_ctx->state.th.length = ARRAY_SIZE(TH_3);
	memcpy(init_ctx->state.th.value, TH_3, ARRAY_SIZE(TH_3));

	init_ctx->state.prk_state = EDHOC_PRK_STATE_3E2M;
	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_PRK_3E2M,
		       tv_import_derive(PRK_3e2m, ARRAY_SIZE(PRK_3e2m)));

	size_t msg_3_len = 0;
	uint8_t msg_3[ARRAY_SIZE(message_3)] = { 0 };

	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(msg_3),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_3), msg_3_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_3, msg_3, msg_3_len);

	/* Draft: 4 - TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I, CRED_R ). */
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), init_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->state.th.value,
				      init_ctx->state.th.length);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->state.prk_state);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, init_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));
}

TEST(draft_edhoc_psk_08, message_3_process)
{
	/* Required injections. */
	resp_ctx->state.machine = EDHOC_SM_WAIT_M3;
	resp_ctx->negotiation.selected_method = METHOD;

	resp_ctx->state.th.stage = EDHOC_TH_STATE_3;
	resp_ctx->state.th.length = ARRAY_SIZE(TH_3);
	memcpy(resp_ctx->state.th.value, TH_3, ARRAY_SIZE(TH_3));

	resp_ctx->state.prk_state = EDHOC_PRK_STATE_3E2M;
	tv_inject_slot(resp_ctx, EDHOC_KEY_SLOT_PRK_3E2M,
		       tv_import_derive(PRK_3e2m, ARRAY_SIZE(PRK_3e2m)));

	ret = edhoc_message_3_process(resp_ctx, message_3,
				      ARRAY_SIZE(message_3));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), resp_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, resp_ctx->state.th.value,
				      resp_ctx->state.th.length);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->state.prk_state);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));
}

TEST(draft_edhoc_psk_08, message_4_compose)
{
	/* Required injections. */
	resp_ctx->state.machine = EDHOC_SM_COMPLETED;
	resp_ctx->is_oscore_export_allowed = true;

	resp_ctx->state.th.stage = EDHOC_TH_STATE_4;
	resp_ctx->state.th.length = ARRAY_SIZE(TH_4);
	memcpy(resp_ctx->state.th.value, TH_4, ARRAY_SIZE(TH_4));

	resp_ctx->state.prk_state = EDHOC_PRK_STATE_4E3M;
	tv_inject_slot(resp_ctx, EDHOC_KEY_SLOT_PRK_4E3M,
		       tv_import_derive(PRK_4e3m, ARRAY_SIZE(PRK_4e3m)));

	size_t msg_4_len = 0;
	uint8_t msg_4[ARRAY_SIZE(message_4)] = { 0 };

	ret = edhoc_message_4_compose(resp_ctx, msg_4, ARRAY_SIZE(msg_4),
				      &msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_4), msg_4_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_4, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), resp_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, resp_ctx->state.th.value,
				      resp_ctx->state.th.length);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->state.prk_state);
}

TEST(draft_edhoc_psk_08, message_4_process)
{
	/* Required injections. */
	init_ctx->state.machine = EDHOC_SM_COMPLETED;
	init_ctx->is_oscore_export_allowed = true;

	init_ctx->state.th.stage = EDHOC_TH_STATE_4;
	init_ctx->state.th.length = ARRAY_SIZE(TH_4);
	memcpy(init_ctx->state.th.value, TH_4, ARRAY_SIZE(TH_4));

	init_ctx->state.prk_state = EDHOC_PRK_STATE_4E3M;
	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_PRK_4E3M,
		       tv_import_derive(PRK_4e3m, ARRAY_SIZE(PRK_4e3m)));

	ret = edhoc_message_4_process(init_ctx, message_4,
				      ARRAY_SIZE(message_4));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), init_ctx->state.th.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->state.th.value,
				      init_ctx->state.th.length);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->state.prk_state);
}

TEST(draft_edhoc_psk_08, exporters)
{
	/* Required injections. */
	init_ctx->state.machine = EDHOC_SM_PERSISTED;
	init_ctx->is_oscore_export_allowed = true;

	init_ctx->state.th.stage = EDHOC_TH_STATE_4;
	init_ctx->state.th.length = ARRAY_SIZE(TH_4);
	memcpy(init_ctx->state.th.value, TH_4, ARRAY_SIZE(TH_4));

	init_ctx->state.prk_state = EDHOC_PRK_STATE_4E3M;
	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_PRK_4E3M,
		       tv_import_derive(PRK_4e3m, ARRAY_SIZE(PRK_4e3m)));

	resp_ctx->state.machine = EDHOC_SM_PERSISTED;
	resp_ctx->is_oscore_export_allowed = true;

	resp_ctx->state.th.stage = EDHOC_TH_STATE_4;
	resp_ctx->state.th.length = ARRAY_SIZE(TH_4);
	memcpy(resp_ctx->state.th.value, TH_4, ARRAY_SIZE(TH_4));

	resp_ctx->state.prk_state = EDHOC_PRK_STATE_4E3M;
	tv_inject_slot(resp_ctx, EDHOC_KEY_SLOT_PRK_4E3M,
		       tv_import_derive(PRK_4e3m, ARRAY_SIZE(PRK_4e3m)));

	/* Draft: 6 - rPSK, raw form. */
	uint8_t init_rpsk[ARRAY_SIZE(rPSK)] = { 0 };
	uint8_t resp_rpsk[ARRAY_SIZE(rPSK)] = { 0 };

	ret = edhoc_export_resumption_psk_raw(init_ctx, init_rpsk,
					      ARRAY_SIZE(init_rpsk));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rPSK, init_rpsk, ARRAY_SIZE(init_rpsk));

	ret = edhoc_export_resumption_psk_raw(resp_ctx, resp_rpsk,
					      ARRAY_SIZE(resp_rpsk));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rPSK, resp_rpsk, ARRAY_SIZE(resp_rpsk));

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->state.prk_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->state.prk_state);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, init_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, PRK_out,
				     ARRAY_SIZE(PRK_out));
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, PRK_out,
				     ARRAY_SIZE(PRK_out));

	/* Draft: 6 - rKID, raw form; it has no key-handle form. */
	uint8_t init_rkid[ARRAY_SIZE(rKID)] = { 0 };
	uint8_t resp_rkid[ARRAY_SIZE(rKID)] = { 0 };

	ret = edhoc_export_resumption_kid_raw(init_ctx, init_rkid,
					      ARRAY_SIZE(init_rkid));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rKID, init_rkid, ARRAY_SIZE(init_rkid));

	ret = edhoc_export_resumption_kid_raw(resp_ctx, resp_rkid,
					      ARRAY_SIZE(resp_rkid));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rKID, resp_rkid, ARRAY_SIZE(resp_rkid));

	/* rPSK, key-handle form. AEAD usage derives the cipher suite AEAD key
	 * length, which is what the draft vector is. */
	uint8_t init_psk_key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	uint8_t resp_psk_key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	ret = edhoc_export_resumption_psk(init_ctx, EDHOC_KEY_USAGE_AEAD,
					  init_psk_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_resumption_psk(resp_ctx, EDHOC_KEY_USAGE_AEAD,
					  resp_psk_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	tv_assert_handles_equal(EDHOC_CIPHER_SUITE_2, init_psk_key_id,
				resp_psk_key_id);

	const psa_key_id_t rpsk_ref = tv_import_aead(rPSK, ARRAY_SIZE(rPSK));

	tv_assert_handles_equal(EDHOC_CIPHER_SUITE_2, init_psk_key_id,
				(const uint8_t *)&rpsk_ref);

	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_destroy_key(rpsk_ref));

	/* The exporter hands ownership of the key handle to the caller. */
	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, init_psk_key_id));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, resp_psk_key_id));
}

TEST(draft_edhoc_psk_08, handshake)
{
	uint8_t buffer[200] = { 0 };

	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;

	/* EDHOC message 1 compose. */
	ret = edhoc_message_1_compose(init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_1), msg_1_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_1, msg_1, msg_1_len);

	/* EDHOC message 1 process. */
	ret = edhoc_message_1_process(resp_ctx, msg_1, msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(METHOD, resp_ctx->negotiation.selected_method);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;

	/* EDHOC message 2 compose. */
	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_2), msg_2_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_2, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_3, resp_ctx->state.th.value,
				      resp_ctx->state.th.length);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));

	/* EDHOC message 2 process. */
	ret = edhoc_message_2_process(init_ctx, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->state.machine);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_3, init_ctx->state.th.value,
				      init_ctx->state.th.length);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, init_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));

	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;

	/* EDHOC message 3 compose. */
	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_3), msg_3_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_3, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->state.th.value,
				      init_ctx->state.th.length);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, init_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));

	/* EDHOC message 3 process. */
	ret = edhoc_message_3_process(resp_ctx, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->state.machine);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, resp_ctx->state.th.value,
				      resp_ctx->state.th.length);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));

	memset(buffer, 0, sizeof(buffer));
	size_t msg_4_len = 0;
	uint8_t *msg_4 = buffer;

	/* EDHOC message 4 compose. */
	ret = edhoc_message_4_compose(resp_ctx, msg_4, ARRAY_SIZE(buffer),
				      &msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_4), msg_4_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_4, msg_4, msg_4_len);

	/* EDHOC message 4 process. */
	ret = edhoc_message_4_process(init_ctx, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->state.machine);

	/* Draft: 6 - both peers derive the same resumption parameters. */
	uint8_t init_rpsk[ARRAY_SIZE(rPSK)] = { 0 };
	uint8_t resp_rpsk[ARRAY_SIZE(rPSK)] = { 0 };
	uint8_t init_rkid[ARRAY_SIZE(rKID)] = { 0 };
	uint8_t resp_rkid[ARRAY_SIZE(rKID)] = { 0 };

	ret = edhoc_export_resumption_psk_raw(init_ctx, init_rpsk,
					      ARRAY_SIZE(init_rpsk));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_resumption_psk_raw(resp_ctx, resp_rpsk,
					      ARRAY_SIZE(resp_rpsk));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_resumption_kid_raw(init_ctx, init_rkid,
					      ARRAY_SIZE(init_rkid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_resumption_kid_raw(resp_ctx, resp_rkid,
					      ARRAY_SIZE(resp_rkid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(rPSK, init_rpsk, ARRAY_SIZE(init_rpsk));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rPSK, resp_rpsk, ARRAY_SIZE(resp_rpsk));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rKID, init_rkid, ARRAY_SIZE(init_rkid));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(rKID, resp_rkid, ARRAY_SIZE(resp_rkid));

	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, init_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, PRK_out,
				     ARRAY_SIZE(PRK_out));
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_2, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, PRK_out,
				     ARRAY_SIZE(PRK_out));
}

TEST_GROUP_RUNNER(draft_edhoc_psk_08)
{
	RUN_TEST_CASE(draft_edhoc_psk_08, message_1_compose);
	RUN_TEST_CASE(draft_edhoc_psk_08, message_1_process);
	RUN_TEST_CASE(draft_edhoc_psk_08, message_2_compose);
	RUN_TEST_CASE(draft_edhoc_psk_08, message_2_process);
	RUN_TEST_CASE(draft_edhoc_psk_08, message_3_compose);
	RUN_TEST_CASE(draft_edhoc_psk_08, message_3_process);
	RUN_TEST_CASE(draft_edhoc_psk_08, message_4_compose);
	RUN_TEST_CASE(draft_edhoc_psk_08, message_4_process);
	RUN_TEST_CASE(draft_edhoc_psk_08, exporters);
	RUN_TEST_CASE(draft_edhoc_psk_08, handshake);
}
