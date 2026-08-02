/**
 * \file    test_message_paths.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for uncovered code paths in EDHOC message compose/process.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

#define EAD_TOKEN_BUFFER_LEN (300)
#define MAX_NR_OF_EAD_TOKENS (3)
#define MSG1_EAD_LABEL (100)
#define MSG4_EAD_LABEL (200)

/* Module types and type definitiones -------------------------------------- */

struct ead_token_buf {
	int32_t label;
	uint8_t value[EAD_TOKEN_BUFFER_LEN];
	size_t value_length;
};

struct ead_context {
	struct edhoc_call_context call_context;
	size_t recv_tokens;
	struct ead_token_buf token[MAX_NR_OF_EAD_TOKENS];
};

/* Static function declarations -------------------------------------------- */

static void test_platform_zeroize(void *buffer, size_t length);
static const struct edhoc_platform *test_get_platform(void);
static int
test_auth_cred_select_local_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_credential_selected *selected);
static int test_auth_cred_authenticate_peer_stub(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted);
static int test_ead_compose_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_ead_token *ead_token,
				 size_t ead_token_size, size_t *ead_token_len);
static int test_ead_process_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 const struct edhoc_ead_token *ead_token,
				 size_t ead_token_size);
static int ead_compose_msg1(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len);
static int ead_process_track(void *user_ctx,
			     const struct edhoc_call_context *call_ctx,
			     const struct edhoc_ead_token *ead_token,
			     size_t ead_token_size);
static int ead_compose_msg4(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len);
static int
ead_compose_value_without_buffer(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_ead_token *ead_token,
				 size_t ead_token_size, size_t *ead_token_len);
static void inject_prk_4e3m(struct edhoc_context *ctx, const uint8_t *prk,
			    size_t prk_len);
static void setup_initiator(struct edhoc_context *ctx);
static void setup_responder(struct edhoc_context *ctx);

/* Module interface variables and constants -------------------------------- */

static const uint8_t msg1_ead_value[] = { 0x01, 0x02, 0x03 };
static const uint8_t msg4_ead_value[] = { 0xff, 0xee, 0xdd };

static const struct edhoc_platform test_platform = {
	.zeroize = test_platform_zeroize,
};

static const struct edhoc_credentials test_cred_stubs = {
	.select_local = test_auth_cred_select_local_stub,
	.authenticate_peer = test_auth_cred_authenticate_peer_stub,
};

/* Static function definitions --------------------------------------------- */

static void test_platform_zeroize(void *buffer, size_t length)
{
	(void)memset(buffer, 0, length);
}

static const struct edhoc_platform *test_get_platform(void)
{
	return &test_platform;
}

static int
test_auth_cred_select_local_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_credential_selected *selected)
{
	static const uint8_t dummy_cert[] = { 0x30, 0x00 };

	(void)user_ctx;
	(void)call_ctx;

	if (NULL == selected) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	selected->label = EDHOC_COSE_HEADER_X509_CHAIN;
	selected->x509_chain.count = 1;
	selected->x509_chain.certificate[0].value = dummy_cert;
	selected->x509_chain.certificate[0].length = ARRAY_SIZE(dummy_cert);

	memset(selected->private_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return EDHOC_SUCCESS;
}

static int test_auth_cred_authenticate_peer_stub(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	static const uint8_t dummy_key[32] = { 0 };

	(void)user_ctx;
	(void)call_ctx;
	(void)received;

	if (NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	trusted->public_key.value = dummy_key;
	trusted->public_key.length = ARRAY_SIZE(dummy_key);

	return EDHOC_SUCCESS;
}

static int test_ead_compose_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_ead_token *ead_token,
				 size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)ead_token;
	(void)ead_token_size;

	if (NULL == ead_token_len) {
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	*ead_token_len = 0;

	return EDHOC_SUCCESS;
}

static int test_ead_process_stub(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 const struct edhoc_ead_token *ead_token,
				 size_t ead_token_size)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)ead_token;
	(void)ead_token_size;

	return EDHOC_SUCCESS;
}

static int ead_compose_msg1(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)ead_token_size;

	if (EDHOC_MESSAGE_1 == call_ctx->message) {
		ead_token[0].label = MSG1_EAD_LABEL;
		ead_token[0].value.value = msg1_ead_value;
		ead_token[0].value.length = ARRAY_SIZE(msg1_ead_value);
		*ead_token_len = 1;
	} else {
		*ead_token_len = 0;
	}

	return EDHOC_SUCCESS;
}

static int ead_process_track(void *user_ctx,
			     const struct edhoc_call_context *call_ctx,
			     const struct edhoc_ead_token *ead_token,
			     size_t ead_token_size)
{
	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->call_context = *call_ctx;
	ead_ctx->recv_tokens = ead_token_size;

	for (size_t i = 0; i < ead_token_size && i < MAX_NR_OF_EAD_TOKENS;
	     ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_length = ead_token[i].value.length;
		if (ead_token[i].value.length > 0 &&
		    ead_token[i].value.length <= EAD_TOKEN_BUFFER_LEN)
			memcpy(ead_ctx->token[i].value,
			       ead_token[i].value.value,
			       ead_token[i].value.length);
	}

	return EDHOC_SUCCESS;
}

static int ead_compose_msg4(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)ead_token_size;

	if (EDHOC_MESSAGE_4 == call_ctx->message) {
		ead_token[0].label = MSG4_EAD_LABEL;
		ead_token[0].value.value = msg4_ead_value;
		ead_token[0].value.length = ARRAY_SIZE(msg4_ead_value);
		*ead_token_len = 1;
	} else {
		*ead_token_len = 0;
	}

	return EDHOC_SUCCESS;
}

static int
ead_compose_value_without_buffer(void *user_ctx,
				 const struct edhoc_call_context *call_ctx,
				 struct edhoc_ead_token *ead_token,
				 size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)ead_token_size;

	ead_token[0].label = MSG1_EAD_LABEL;
	ead_token[0].value.value = NULL;
	ead_token[0].value.length = ARRAY_SIZE(msg1_ead_value);
	*ead_token_len = 1;

	return EDHOC_SUCCESS;
}

static void inject_prk_4e3m(struct edhoc_context *ctx, const uint8_t *prk,
			    size_t prk_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&attr, prk, prk_len, &kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	struct edhoc_key_slot *slot = &ctx->key_slots[EDHOC_KEY_SLOT_PRK_4E3M];
	memcpy(slot->key_id, &kid, sizeof(kid));
	slot->present = true;
}

static void setup_initiator(struct edhoc_context *ctx)
{
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};

	int ret = edhoc_context_init(ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(
		ctx, edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2), 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

static void setup_responder(struct edhoc_context *ctx)
{
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};

	int ret = edhoc_context_init(ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(
		ctx, edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2), 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(message_paths);

TEST_SETUP(message_paths)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(message_paths)
{
	mbedtls_psa_crypto_free();
}

TEST(message_paths, msg1_compose_bstr_cid)
{
	struct edhoc_context ctx = { 0 };
	setup_initiator(&ctx);

	const struct edhoc_connection_id bstr_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	int ret = edhoc_set_connection_id(&ctx, &bstr_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_1_compose(&ctx, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_compose_multiple_cipher_suites)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	ret = edhoc_set_methods(&ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_cipher_suite csuites[2] = {
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2),
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2),
	};
	csuites[0].value = 0;
	ret = edhoc_set_cipher_suites(&ctx, csuites, ARRAY_SIZE(csuites));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		&ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_1_compose(&ctx, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_compose_with_ead)
{
	struct edhoc_context ctx = { 0 };
	setup_initiator(&ctx);

	const struct edhoc_ead ead = {
		.compose = ead_compose_msg1,
		.process = test_ead_process_stub,
	};
	int ret = edhoc_bind_ead(&ctx, &ead);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_1_compose(&ctx, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_process_bstr_cid)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_initiator(&init_ctx);
	setup_responder(&resp_ctx);

	const struct edhoc_connection_id bstr_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	int ret = edhoc_set_connection_id(&init_ctx, &bstr_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5,
	};
	ret = edhoc_set_connection_id(&resp_ctx, &resp_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_1_compose(&init_ctx, msg, ARRAY_SIZE(msg),
				      &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
			  resp_ctx.negotiation.peer_connection_id.encode_type);
	TEST_ASSERT_EQUAL(bstr_cid.bstr_length,
			  resp_ctx.negotiation.peer_connection_id.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		bstr_cid.bstr_value,
		resp_ctx.negotiation.peer_connection_id.bstr_value,
		bstr_cid.bstr_length);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_compose_ead_value_without_buffer)
{
	struct edhoc_context init_ctx = { 0 };

	setup_initiator(&init_ctx);

	const struct edhoc_ead ead = {
		.compose = ead_compose_value_without_buffer,
		.process = test_ead_process_stub,
	};
	int ret = edhoc_bind_ead(&init_ctx, &ead);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_1_compose(&init_ctx, msg, ARRAY_SIZE(msg),
				      &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_process_with_ead)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	struct ead_context ead_ctx = { 0 };

	setup_initiator(&init_ctx);
	setup_responder(&resp_ctx);

	const struct edhoc_ead ead_init = {
		.compose = ead_compose_msg1,
		.process = test_ead_process_stub,
	};
	int ret = edhoc_bind_ead(&init_ctx, &ead_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead_resp = {
		.compose = test_ead_compose_stub,
		.process = ead_process_track,
	};
	ret = edhoc_bind_ead(&resp_ctx, &ead_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_user_context(&resp_ctx, &ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_1_compose(&init_ctx, msg, ARRAY_SIZE(msg),
				      &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ROLE_RESPONDER, ead_ctx.call_context.role);
	TEST_ASSERT_EQUAL(EDHOC_METHOD_0, ead_ctx.call_context.method);
	TEST_ASSERT_EQUAL(EDHOC_CIPHER_SUITE_2,
			  ead_ctx.call_context.selected_cipher_suite);
	TEST_ASSERT_EQUAL(EDHOC_MESSAGE_1, ead_ctx.call_context.message);
	TEST_ASSERT_EQUAL(1, ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(MSG1_EAD_LABEL, ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(msg1_ead_value),
			  ead_ctx.token[0].value_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(msg1_ead_value, ead_ctx.token[0].value,
				      ARRAY_SIZE(msg1_ead_value));

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_process_bad_state)
{
	struct edhoc_context init_ctx = { 0 };
	setup_initiator(&init_ctx);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg, ARRAY_SIZE(msg),
					  &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_context resp_ctx = { 0 };
	setup_responder(&resp_ctx);
	resp_ctx.state.machine = EDHOC_SM_COMPLETED;

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_process_no_cipher_suites)
{
	struct edhoc_context init_ctx = { 0 };
	setup_initiator(&init_ctx);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg, ARRAY_SIZE(msg),
					  &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_context resp_ctx = { 0 };
	setup_responder(&resp_ctx);
	resp_ctx.negotiation.cipher_suite.count = 0;

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg1_roundtrip_bstr_cid_and_ead)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	struct ead_context ead_ctx = { 0 };

	setup_initiator(&init_ctx);
	setup_responder(&resp_ctx);

	const struct edhoc_connection_id bstr_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	int ret = edhoc_set_connection_id(&init_ctx, &bstr_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 7,
	};
	ret = edhoc_set_connection_id(&resp_ctx, &resp_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead_init = {
		.compose = ead_compose_msg1,
		.process = test_ead_process_stub,
	};
	ret = edhoc_bind_ead(&init_ctx, &ead_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead_resp = {
		.compose = test_ead_compose_stub,
		.process = ead_process_track,
	};
	ret = edhoc_bind_ead(&resp_ctx, &ead_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_user_context(&resp_ctx, &ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_1_compose(&init_ctx, msg, ARRAY_SIZE(msg),
				      &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
			  resp_ctx.negotiation.peer_connection_id.encode_type);
	TEST_ASSERT_EQUAL(bstr_cid.bstr_length,
			  resp_ctx.negotiation.peer_connection_id.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		bstr_cid.bstr_value,
		resp_ctx.negotiation.peer_connection_id.bstr_value,
		bstr_cid.bstr_length);
	TEST_ASSERT_EQUAL(EDHOC_MESSAGE_1, ead_ctx.call_context.message);
	TEST_ASSERT_EQUAL(1, ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(MSG1_EAD_LABEL, ead_ctx.token[0].label);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg4_compose_with_ead)
{
	struct edhoc_context ctx = { 0 };
	setup_responder(&ctx);

	const struct edhoc_ead ead = {
		.compose = ead_compose_msg4,
		.process = test_ead_process_stub,
	};
	int ret = edhoc_bind_ead(&ctx, &ead);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t th[32] = { 0 };
	uint8_t prk[32] = { 0 };
	memset(th, 0xAA, sizeof(th));
	memset(prk, 0xBB, sizeof(prk));

	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = sizeof(th);
	ctx.negotiation.selected_cipher_suite_index = 0;
	memcpy(ctx.state.th.value, th, sizeof(th));
	inject_prk_4e3m(&ctx, prk, sizeof(prk));

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_4_compose(&ctx, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, ctx.state.machine);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg4_compose_process_roundtrip)
{
	uint8_t th[32] = { 0 };
	uint8_t prk[32] = { 0 };
	memset(th, 0x11, sizeof(th));
	memset(prk, 0x22, sizeof(prk));

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_context init_ctx = { 0 };

	setup_responder(&resp_ctx);
	setup_initiator(&init_ctx);

	resp_ctx.state.machine = EDHOC_SM_COMPLETED;
	resp_ctx.state.role = EDHOC_ROLE_RESPONDER;
	resp_ctx.state.th.stage = EDHOC_TH_STATE_4;
	resp_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.state.th.length = sizeof(th);
	resp_ctx.negotiation.selected_cipher_suite_index = 0;
	memcpy(resp_ctx.state.th.value, th, sizeof(th));
	inject_prk_4e3m(&resp_ctx, prk, sizeof(prk));

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_4_compose(&resp_ctx, msg, ARRAY_SIZE(msg),
					  &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.state.machine = EDHOC_SM_COMPLETED;
	init_ctx.state.role = EDHOC_ROLE_INITIATOR;
	init_ctx.state.th.stage = EDHOC_TH_STATE_4;
	init_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	init_ctx.state.th.length = sizeof(th);
	init_ctx.negotiation.selected_cipher_suite_index = 0;
	memcpy(init_ctx.state.th.value, th, sizeof(th));
	inject_prk_4e3m(&init_ctx, prk, sizeof(prk));

	ret = edhoc_message_4_process(&init_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx.state.machine);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(message_paths, msg4_compose_process_roundtrip_with_ead)
{
	uint8_t th[32] = { 0 };
	uint8_t prk[32] = { 0 };
	memset(th, 0x33, sizeof(th));
	memset(prk, 0x44, sizeof(prk));

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_context init_ctx = { 0 };
	struct ead_context ead_ctx = { 0 };

	setup_responder(&resp_ctx);
	setup_initiator(&init_ctx);

	const struct edhoc_ead ead_resp = {
		.compose = ead_compose_msg4,
		.process = test_ead_process_stub,
	};
	int ret = edhoc_bind_ead(&resp_ctx, &ead_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead_init = {
		.compose = test_ead_compose_stub,
		.process = ead_process_track,
	};
	ret = edhoc_bind_ead(&init_ctx, &ead_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_user_context(&init_ctx, &ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.state.machine = EDHOC_SM_COMPLETED;
	resp_ctx.state.role = EDHOC_ROLE_RESPONDER;
	resp_ctx.state.th.stage = EDHOC_TH_STATE_4;
	resp_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.state.th.length = sizeof(th);
	resp_ctx.negotiation.selected_cipher_suite_index = 0;
	memcpy(resp_ctx.state.th.value, th, sizeof(th));
	inject_prk_4e3m(&resp_ctx, prk, sizeof(prk));

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg, ARRAY_SIZE(msg),
				      &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.state.machine = EDHOC_SM_COMPLETED;
	init_ctx.state.role = EDHOC_ROLE_INITIATOR;
	init_ctx.state.th.stage = EDHOC_TH_STATE_4;
	init_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	init_ctx.state.th.length = sizeof(th);
	init_ctx.negotiation.selected_cipher_suite_index = 0;
	memcpy(init_ctx.state.th.value, th, sizeof(th));
	inject_prk_4e3m(&init_ctx, prk, sizeof(prk));

	ret = edhoc_message_4_process(&init_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx.state.machine);
	TEST_ASSERT_EQUAL(EDHOC_ROLE_INITIATOR, ead_ctx.call_context.role);
	TEST_ASSERT_EQUAL(EDHOC_METHOD_0, ead_ctx.call_context.method);
	TEST_ASSERT_EQUAL(EDHOC_CIPHER_SUITE_2,
			  ead_ctx.call_context.selected_cipher_suite);
	TEST_ASSERT_EQUAL(EDHOC_MESSAGE_4, ead_ctx.call_context.message);
	TEST_ASSERT_EQUAL(1, ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(MSG4_EAD_LABEL, ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(msg4_ead_value),
			  ead_ctx.token[0].value_length);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(message_paths)
{
	/* edhoc_message_1_compose */
	RUN_TEST_CASE(message_paths, msg1_compose_bstr_cid);
	RUN_TEST_CASE(message_paths, msg1_compose_multiple_cipher_suites);
	RUN_TEST_CASE(message_paths, msg1_compose_with_ead);

	/* edhoc_message_1_process */
	RUN_TEST_CASE(message_paths, msg1_process_bstr_cid);
	RUN_TEST_CASE(message_paths, msg1_compose_ead_value_without_buffer);
	RUN_TEST_CASE(message_paths, msg1_process_with_ead);
	RUN_TEST_CASE(message_paths, msg1_process_bad_state);
	RUN_TEST_CASE(message_paths, msg1_process_no_cipher_suites);
	RUN_TEST_CASE(message_paths, msg1_roundtrip_bstr_cid_and_ead);

	/* edhoc_message_4_compose / edhoc_message_4_process */
	RUN_TEST_CASE(message_paths, msg4_compose_with_ead);
	RUN_TEST_CASE(message_paths, msg4_compose_process_roundtrip);
	RUN_TEST_CASE(message_paths, msg4_compose_process_roundtrip_with_ead);
}
