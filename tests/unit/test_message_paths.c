/**
 * \file    test_message_paths.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for uncovered code paths in EDHOC message compose/process.
 *
 *          Exercises: msg1 bstr CID, multiple cipher suites, EAD,
 *          msg4 compose/process.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 *
 */

/* Include files ----------------------------------------------------------- */

#include "test_common.h"
#include "edhoc_cipher_suite_0.h"
#include "edhoc_cipher_suite_2.h"
#include "test_ead.h"

#include <psa/crypto.h>

static const struct edhoc_cipher_suite test_cipher_suite_0 = {
	.value = 0,
	.aead_key_length = 16,
	.aead_tag_length = 8,
	.aead_iv_length = 13,
	.hash_length = 32,
	.mac_length = 8,
	.ecc_key_length = 32,
	.ecc_sign_length = 64,
};

static const struct edhoc_cipher_suite test_cipher_suite_2 = {
	.value = 2,
	.aead_key_length = 16,
	.aead_tag_length = 8,
	.aead_iv_length = 13,
	.hash_length = 32,
	.mac_length = 8,
	.ecc_key_length = 32,
	.ecc_sign_length = 64,
};

static int ead_compose_msg1(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)ead_token_size;
	if (EDHOC_MSG_1 == msg) {
		static const uint8_t val[] = { 0x01, 0x02, 0x03 };
		ead_token[0].label = 100;
		ead_token[0].value = val;
		ead_token[0].value_len = sizeof(val);
		*ead_token_len = 1;
	} else {
		*ead_token_len = 0;
	}
	return EDHOC_SUCCESS;
}

static int ead_process_track(void *user_ctx, enum edhoc_message msg,
			     const struct edhoc_ead_token *ead_token,
			     size_t ead_token_size)
{
	struct ead_context *ead_ctx = user_ctx;
	ead_ctx->msg = msg;
	ead_ctx->recv_tokens = ead_token_size;
	for (size_t i = 0; i < ead_token_size && i < MAX_NR_OF_EAD_TOKENS;
	     ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_len = ead_token[i].value_len;
		if (ead_token[i].value_len > 0 &&
		    ead_token[i].value_len <= EAD_TOKEN_BUFFER_LEN)
			memcpy(ead_ctx->token[i].value, ead_token[i].value,
			       ead_token[i].value_len);
	}
	return EDHOC_SUCCESS;
}

static int ead_compose_msg4(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)ead_token_size;
	if (EDHOC_MSG_4 == msg) {
		static const uint8_t val[] = { 0xff, 0xee, 0xdd };
		ead_token[0].label = 200;
		ead_token[0].value = val;
		ead_token[0].value_len = sizeof(val);
		*ead_token_len = 1;
	} else {
		*ead_token_len = 0;
	}
	return EDHOC_SUCCESS;
}

static void setup_initiator_suite0(struct edhoc_context *ctx)
{
	edhoc_context_init(ctx);
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(ctx, methods, 1);
	edhoc_set_cipher_suites(ctx, &test_cipher_suite_0, 1);
	edhoc_bind_keys(ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_crypto(ctx, edhoc_cipher_suite_0_get_crypto());
}

static void setup_responder_suite0(struct edhoc_context *ctx)
{
	edhoc_context_init(ctx);
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(ctx, methods, 1);
	edhoc_set_cipher_suites(ctx, &test_cipher_suite_0, 1);
	edhoc_bind_keys(ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_crypto(ctx, edhoc_cipher_suite_0_get_crypto());
}

TEST_GROUP(message_paths);

TEST_SETUP(message_paths)
{
	psa_crypto_init();
}

TEST_TEAR_DOWN(message_paths)
{
	mbedtls_psa_crypto_free();
}

/**
 * @scenario  Message 1 compose with byte-string CID.
 * @env       Context with cipher suite 0, byte-string CID, real crypto.
 * @action    Compose message 1.
 * @expected  EDHOC_SUCCESS, msg_1_len > 0.
 */
TEST(message_paths, msg1_compose_bstr_cid)
{
	struct edhoc_context ctx = { 0 };
	setup_initiator_suite0(&ctx);

	struct edhoc_connection_id bstr_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
	};
	bstr_cid.bstr_value[0] = 0x01;
	bstr_cid.bstr_value[1] = 0x02;
	bstr_cid.bstr_value[2] = 0x03;
	edhoc_set_connection_id(&ctx, &bstr_cid);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 1 compose with multiple cipher suites.
 * @env       Context with 2 cipher suites [0, 2], real crypto for suite 2.
 * @action    Compose message 1.
 * @expected  EDHOC_SUCCESS, msg_1_len > 0.
 */
TEST(message_paths, msg1_compose_multiple_cipher_suites)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(&ctx, methods, 1);

	const struct edhoc_cipher_suite csuites[2] = { test_cipher_suite_0,
						       test_cipher_suite_2 };
	edhoc_set_cipher_suites(&ctx, csuites, 2);

	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&ctx, &cid);

	edhoc_bind_keys(&ctx, edhoc_cipher_suite_2_get_keys());
	edhoc_bind_crypto(&ctx, edhoc_cipher_suite_2_get_crypto());

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 1 compose with EAD.
 * @env       Context with EAD compose callback returning 1 token for msg1.
 * @action    Compose message 1.
 * @expected  EDHOC_SUCCESS, msg_1_len > 0.
 */
TEST(message_paths, msg1_compose_with_ead)
{
	struct edhoc_context ctx = { 0 };
	setup_initiator_suite0(&ctx);

	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&ctx, &cid);

	const struct edhoc_ead ead = {
		.compose = ead_compose_msg1,
		.process = test_ead_process_stub,
	};
	edhoc_bind_ead(&ctx, &ead);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 1 process with byte-string CID.
 * @env       Initiator composes msg1 with bstr CID; responder processes.
 * @action    Process message 1.
 * @expected  EDHOC_SUCCESS, peer_cid.encode_type == EDHOC_CID_TYPE_BYTE_STRING.
 */
TEST(message_paths, msg1_process_bstr_cid)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	setup_initiator_suite0(&init_ctx);
	setup_responder_suite0(&resp_ctx);

	struct edhoc_connection_id bstr_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
	};
	bstr_cid.bstr_value[0] = 0x01;
	bstr_cid.bstr_value[1] = 0x02;
	bstr_cid.bstr_value[2] = 0x03;
	edhoc_set_connection_id(&init_ctx, &bstr_cid);

	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5,
	};
	edhoc_set_connection_id(&resp_ctx, &resp_cid);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  resp_ctx.peer_cid.encode_type);
	TEST_ASSERT_EQUAL(3, resp_ctx.peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(bstr_cid.bstr_value,
				      resp_ctx.peer_cid.bstr_value, 3);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Message 1 process with EAD.
 * @env       Initiator composes msg1 with EAD; responder has EAD process callback.
 * @action    Process message 1.
 * @expected  EDHOC_SUCCESS, EAD process callback invoked with correct token.
 */
TEST(message_paths, msg1_process_with_ead)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	struct ead_context ead_ctx = { 0 };

	setup_initiator_suite0(&init_ctx);
	setup_responder_suite0(&resp_ctx);

	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&init_ctx, &cid);
	edhoc_set_connection_id(&resp_ctx, &cid);

	const struct edhoc_ead ead_init = {
		.compose = ead_compose_msg1,
		.process = test_ead_process_stub,
	};
	edhoc_bind_ead(&init_ctx, &ead_init);

	const struct edhoc_ead ead_resp = {
		.compose = test_ead_compose_stub,
		.process = ead_process_track,
	};
	edhoc_bind_ead(&resp_ctx, &ead_resp);
	edhoc_set_user_context(&resp_ctx, &ead_ctx);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(100, ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(3, ead_ctx.token[0].value_len);
	{
		const uint8_t expected[] = { 0x01, 0x02, 0x03 };
		TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, ead_ctx.token[0].value,
					      3);
	}

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  Message 4 compose with EAD.
 * @env       Responder context in COMPLETED, TH_4, PRK_4e3m; EAD compose for msg4.
 * @action    Compose message 4.
 * @expected  EDHOC_SUCCESS, msg_4_len > 0.
 */
TEST(message_paths, msg4_compose_with_ead)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(&ctx, methods, 1);
	edhoc_set_cipher_suites(&ctx, &test_cipher_suite_0, 1);
	edhoc_bind_keys(&ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_crypto(&ctx, edhoc_cipher_suite_0_get_crypto());

	const struct edhoc_ead ead = {
		.compose = ead_compose_msg4,
		.process = test_ead_process_stub,
	};
	edhoc_bind_ead(&ctx, &ead);

	ctx.status = EDHOC_SM_COMPLETED;
	ctx.role = EDHOC_RESPONDER;
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	ctx.chosen_csuite_idx = 0;
	memset(ctx.th, 0xAA, 32);
	memset(ctx.prk, 0xBB, 32);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_4_compose(&ctx, msg, sizeof(msg), &msg_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, ctx.status);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Message 4 compose and process round-trip.
 * @env       Responder composes msg4; initiator processes. Same th/prk on both.
 * @action    Compose msg4, process msg4.
 * @expected  EDHOC_SUCCESS on both.
 */
TEST(message_paths, msg4_compose_process_roundtrip)
{
	uint8_t th[32], prk[32];
	memset(th, 0x11, sizeof(th));
	memset(prk, 0x22, sizeof(prk));

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_context init_ctx = { 0 };

	edhoc_context_init(&resp_ctx);
	edhoc_context_init(&init_ctx);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(&resp_ctx, methods, 1);
	edhoc_set_methods(&init_ctx, methods, 1);
	edhoc_set_cipher_suites(&resp_ctx, &test_cipher_suite_0, 1);
	edhoc_set_cipher_suites(&init_ctx, &test_cipher_suite_0, 1);
	edhoc_bind_keys(&resp_ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_keys(&init_ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_crypto(&resp_ctx, edhoc_cipher_suite_0_get_crypto());
	edhoc_bind_crypto(&init_ctx, edhoc_cipher_suite_0_get_crypto());

	resp_ctx.status = EDHOC_SM_COMPLETED;
	resp_ctx.role = EDHOC_RESPONDER;
	resp_ctx.th_state = EDHOC_TH_STATE_4;
	resp_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.th_len = sizeof(th);
	resp_ctx.prk_len = sizeof(prk);
	resp_ctx.chosen_csuite_idx = 0;
	memcpy(resp_ctx.th, th, sizeof(th));
	memcpy(resp_ctx.prk, prk, sizeof(prk));

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_4_compose(&resp_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_COMPLETED;
	init_ctx.role = EDHOC_INITIATOR;
	init_ctx.th_state = EDHOC_TH_STATE_4;
	init_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	init_ctx.th_len = sizeof(th);
	init_ctx.prk_len = sizeof(prk);
	init_ctx.chosen_csuite_idx = 0;
	memcpy(init_ctx.th, th, sizeof(th));
	memcpy(init_ctx.prk, prk, sizeof(prk));

	ret = edhoc_message_4_process(&init_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx.status);

	edhoc_context_deinit(&resp_ctx);
	edhoc_context_deinit(&init_ctx);
}

/**
 * @scenario  Message 4 compose/process round-trip with EAD.
 * @env       Responder composes msg4 with EAD; initiator processes with EAD callback.
 * @action    Compose msg4 with EAD, process msg4.
 * @expected  EDHOC_SUCCESS on both; EAD process receives token.
 */
TEST(message_paths, msg4_compose_process_roundtrip_with_ead)
{
	uint8_t th[32], prk[32];
	memset(th, 0x33, sizeof(th));
	memset(prk, 0x44, sizeof(prk));

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_context init_ctx = { 0 };
	struct ead_context ead_ctx = { 0 };

	edhoc_context_init(&resp_ctx);
	edhoc_context_init(&init_ctx);

	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(&resp_ctx, methods, 1);
	edhoc_set_methods(&init_ctx, methods, 1);
	edhoc_set_cipher_suites(&resp_ctx, &test_cipher_suite_0, 1);
	edhoc_set_cipher_suites(&init_ctx, &test_cipher_suite_0, 1);
	edhoc_bind_keys(&resp_ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_keys(&init_ctx, edhoc_cipher_suite_0_get_keys());
	edhoc_bind_crypto(&resp_ctx, edhoc_cipher_suite_0_get_crypto());
	edhoc_bind_crypto(&init_ctx, edhoc_cipher_suite_0_get_crypto());

	const struct edhoc_ead ead_resp = {
		.compose = ead_compose_msg4,
		.process = test_ead_process_stub,
	};
	edhoc_bind_ead(&resp_ctx, &ead_resp);

	const struct edhoc_ead ead_init = {
		.compose = test_ead_compose_stub,
		.process = ead_process_track,
	};
	edhoc_bind_ead(&init_ctx, &ead_init);
	edhoc_set_user_context(&init_ctx, &ead_ctx);

	resp_ctx.status = EDHOC_SM_COMPLETED;
	resp_ctx.role = EDHOC_RESPONDER;
	resp_ctx.th_state = EDHOC_TH_STATE_4;
	resp_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.th_len = sizeof(th);
	resp_ctx.prk_len = sizeof(prk);
	resp_ctx.chosen_csuite_idx = 0;
	memcpy(resp_ctx.th, th, sizeof(th));
	memcpy(resp_ctx.prk, prk, sizeof(prk));

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_4_compose(&resp_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_COMPLETED;
	init_ctx.role = EDHOC_INITIATOR;
	init_ctx.th_state = EDHOC_TH_STATE_4;
	init_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	init_ctx.th_len = sizeof(th);
	init_ctx.prk_len = sizeof(prk);
	init_ctx.chosen_csuite_idx = 0;
	memcpy(init_ctx.th, th, sizeof(th));
	memcpy(init_ctx.prk, prk, sizeof(prk));

	ret = edhoc_message_4_process(&init_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx.status);
	TEST_ASSERT_EQUAL(EDHOC_MSG_4, ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(200, ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(3, ead_ctx.token[0].value_len);

	edhoc_context_deinit(&resp_ctx);
	edhoc_context_deinit(&init_ctx);
}

/**
 * @scenario  Message 1 compose + process round-trip with bstr CID and EAD.
 * @env       Initiator composes with bstr CID + EAD; responder processes.
 * @action    Full msg1 round-trip.
 * @expected  EDHOC_SUCCESS; peer_cid and EAD verified.
 */
TEST(message_paths, msg1_roundtrip_bstr_cid_and_ead)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	struct ead_context ead_ctx = { 0 };

	setup_initiator_suite0(&init_ctx);
	setup_responder_suite0(&resp_ctx);

	struct edhoc_connection_id bstr_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
	};
	bstr_cid.bstr_value[0] = 0x01;
	bstr_cid.bstr_value[1] = 0x02;
	bstr_cid.bstr_value[2] = 0x03;
	edhoc_set_connection_id(&init_ctx, &bstr_cid);

	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 7,
	};
	edhoc_set_connection_id(&resp_ctx, &resp_cid);

	const struct edhoc_ead ead_init = {
		.compose = ead_compose_msg1,
		.process = test_ead_process_stub,
	};
	edhoc_bind_ead(&init_ctx, &ead_init);

	const struct edhoc_ead ead_resp = {
		.compose = test_ead_compose_stub,
		.process = ead_process_track,
	};
	edhoc_bind_ead(&resp_ctx, &ead_resp);
	edhoc_set_user_context(&resp_ctx, &ead_ctx);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  resp_ctx.peer_cid.encode_type);
	TEST_ASSERT_EQUAL(3, resp_ctx.peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(bstr_cid.bstr_value,
				      resp_ctx.peer_cid.bstr_value, 3);
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(100, ead_ctx.token[0].label);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg1_process with bad state (context not in START).
 * @env       Responder context with status forced to EDHOC_SM_COMPLETED.
 * @action    Call edhoc_message_1_process with a valid message 1.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(message_paths, msg1_process_bad_state)
{
	struct edhoc_context init_ctx;
	setup_initiator_suite0(&init_ctx);
	const struct edhoc_connection_id cid_i = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&init_ctx, &cid_i);

	uint8_t msg[256];
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_context resp_ctx;
	setup_responder_suite0(&resp_ctx);
	resp_ctx.status = EDHOC_SM_COMPLETED;

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg1_process with garbage CBOR input.
 * @env       Responder context in valid START state.
 * @action    Call edhoc_message_1_process with invalid CBOR bytes.
 * @expected  Returns error (CBOR failure or process failure).
 */
TEST(message_paths, msg1_process_invalid_cbor)
{
	struct edhoc_context resp_ctx;
	setup_responder_suite0(&resp_ctx);
	const struct edhoc_connection_id cid_r = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	edhoc_set_connection_id(&resp_ctx, &cid_r);

	uint8_t garbage[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	int ret = edhoc_message_1_process(&resp_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&resp_ctx);
}

/**
 * @scenario  msg1_process with no cipher suites configured.
 * @env       Responder context initialized but csuite_len forced to 0.
 * @action    Compose valid msg1 from initiator, then process with empty responder.
 * @expected  Returns EDHOC_ERROR_BAD_STATE (no cipher suites).
 */
TEST(message_paths, msg1_process_no_cipher_suites)
{
	struct edhoc_context init_ctx;
	setup_initiator_suite0(&init_ctx);
	const struct edhoc_connection_id cid_i = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	edhoc_set_connection_id(&init_ctx, &cid_i);

	uint8_t msg[256];
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_context resp_ctx;
	setup_responder_suite0(&resp_ctx);
	resp_ctx.csuite_len = 0;

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST_GROUP_RUNNER(message_paths)
{
	RUN_TEST_CASE(message_paths, msg1_compose_bstr_cid);
	RUN_TEST_CASE(message_paths, msg1_compose_multiple_cipher_suites);
	RUN_TEST_CASE(message_paths, msg1_compose_with_ead);
	RUN_TEST_CASE(message_paths, msg1_process_bstr_cid);
	RUN_TEST_CASE(message_paths, msg1_process_with_ead);
	RUN_TEST_CASE(message_paths, msg4_compose_with_ead);
	RUN_TEST_CASE(message_paths, msg4_compose_process_roundtrip);
	RUN_TEST_CASE(message_paths, msg4_compose_process_roundtrip_with_ead);
	RUN_TEST_CASE(message_paths, msg1_roundtrip_bstr_cid_and_ead);
	RUN_TEST_CASE(message_paths, msg1_process_bad_state);
	RUN_TEST_CASE(message_paths, msg1_process_invalid_cbor);
	RUN_TEST_CASE(message_paths, msg1_process_no_cipher_suites);
}
