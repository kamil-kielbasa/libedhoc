/**
 * \file    test_internals_message2.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_2.c internal functions.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "internals_common.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_message2);

TEST_SETUP(internals_message2)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_message2)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_message2, comp_th_2_null)
{
	int ret = comp_th_2(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_th_2_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	int ret = comp_th_2(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, comp_encapsulate_null)
{
	int ret = comp_encapsulate(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_decapsulate_null)
{
	int ret = comp_decapsulate(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_keystream_null)
{
	uint8_t ks[64] = { 0 };
	int ret = comp_keystream(NULL, ks, ARRAY_SIZE(ks));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_keystream_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;

	uint8_t ks[64] = { 0 };
	int ret = comp_keystream(&ctx, ks, ARRAY_SIZE(ks));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, comp_grx_null)
{
	int ret = comp_grx(NULL, NULL, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_grx_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.role = 99;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = comp_grx(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, comp_plaintext_2_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	size_t len = 0;

	int ret = comp_plaintext_2_len(NULL, mc, 8, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_plaintext_2_len(&ctx, NULL, 8, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_plaintext_2_len(&ctx, mc, 0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_plaintext_2_len(&ctx, mc, 8, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, prepare_message_2_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t ctxt[64] = { 0 };
	uint8_t msg[128] = { 0 };
	size_t msg_len = 0;

	int ret = prepare_message_2(NULL, ctxt, ARRAY_SIZE(ctxt), msg,
				    ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_message_2(&ctx, NULL, ARRAY_SIZE(ctxt), msg,
				ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_message_2(&ctx, ctxt, 0, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_message_2(&ctx, ctxt, ARRAY_SIZE(ctxt), NULL,
				ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_message_2(&ctx, ctxt, ARRAY_SIZE(ctxt), msg, 0, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_message_2(&ctx, ctxt, ARRAY_SIZE(ctxt), msg,
				ARRAY_SIZE(msg), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, parse_plaintext_2_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	int ret = parse_plaintext_2(NULL, ptxt, ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_plaintext_2(&ctx, NULL, ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_plaintext_2(&ctx, ptxt, 0, &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_plaintext_2(&ctx, ptxt, ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, parse_plaintext_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret =
		parse_plaintext_2(&ctx, garbage, ARRAY_SIZE(garbage), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, parse_msg_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const uint8_t garbage[] = { 0x18 };
	uint8_t ctxt[64] = { 0 };

	int ret = parse_msg_2(&ctx, garbage, ARRAY_SIZE(garbage), ctxt,
			      ARRAY_SIZE(ctxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, prepare_plaintext_2_invalid_cid)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.negotiation.connection_id.encode_type = 99;

	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;

	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->id_cred_comp[0] = 0x05;
	mc->id_cred_comp_len = 1;

	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256] = { 0 };
	size_t ptxt_len = 0;

	int ret = prepare_plaintext_2(&ctx, mc, sign, ARRAY_SIZE(sign), ptxt,
				      ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_message2)
{
	RUN_TEST_CASE(internals_message2, comp_th_2_null);
	RUN_TEST_CASE(internals_message2, comp_th_2_bad_state);
	RUN_TEST_CASE(internals_message2, comp_encapsulate_null);
	RUN_TEST_CASE(internals_message2, comp_decapsulate_null);
	RUN_TEST_CASE(internals_message2, comp_keystream_null);
	RUN_TEST_CASE(internals_message2, comp_keystream_bad_th_state);
	RUN_TEST_CASE(internals_message2, comp_grx_null);
	RUN_TEST_CASE(internals_message2, comp_grx_invalid_role);
	RUN_TEST_CASE(internals_message2, comp_plaintext_2_len_null);
	RUN_TEST_CASE(internals_message2, prepare_message_2_null);
	RUN_TEST_CASE(internals_message2, parse_plaintext_2_null);
	RUN_TEST_CASE(internals_message2, parse_plaintext_2_garbage);
	RUN_TEST_CASE(internals_message2, parse_msg_2_garbage);
	RUN_TEST_CASE(internals_message2, prepare_plaintext_2_invalid_cid);
}
