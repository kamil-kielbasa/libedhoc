/**
 * \file    test_internals_message3.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_3.c internal functions.
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

TEST_GROUP(internals_message3);

TEST_SETUP(internals_message3)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_message3)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_message3, comp_th_3_null)
{
	int ret = comp_th_3(NULL, NULL, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, comp_th_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;

	uint8_t buf[512] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	mc->th_len = 32;

	uint8_t ptxt[32] = { 0 };
	int ret = comp_th_3(&ctx, mc, ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, comp_key_iv_aad_3_null)
{
	uint8_t key[16] = { 0 };
	uint8_t iv[13] = { 0 };
	uint8_t aad[256] = { 0 };
	int ret = comp_key_iv_aad_3(NULL, key, ARRAY_SIZE(key), iv,
				    ARRAY_SIZE(iv), aad, ARRAY_SIZE(aad));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, comp_key_iv_aad_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t key[16] = { 0 };
	uint8_t iv[13] = { 0 };
	uint8_t aad[256] = { 0 };
	int ret = comp_key_iv_aad_3(&ctx, key, ARRAY_SIZE(key), iv,
				    ARRAY_SIZE(iv), aad, ARRAY_SIZE(aad));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, comp_plaintext_3_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	size_t len = 0;

	int ret = comp_plaintext_3_len(NULL, mc, 8, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_plaintext_3_len(&ctx, NULL, 8, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_plaintext_3_len(&ctx, mc, 0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_plaintext_3_len(&ctx, mc, 8, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, prepare_plaintext_3_null)
{
	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256] = { 0 };
	size_t ptxt_len = 0;

	int ret = prepare_plaintext_3(NULL, sign, ARRAY_SIZE(sign), ptxt,
				      ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_plaintext_3(mc, NULL, ARRAY_SIZE(sign), ptxt,
				  ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_plaintext_3(mc, sign, 0, ptxt, ARRAY_SIZE(ptxt),
				  &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_plaintext_3(mc, sign, ARRAY_SIZE(sign), NULL,
				  ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_plaintext_3(mc, sign, ARRAY_SIZE(sign), ptxt, 0,
				  &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_plaintext_3(mc, sign, ARRAY_SIZE(sign), ptxt,
				  ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, comp_aad_3_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	size_t len = 0;

	int ret = comp_aad_3_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_aad_3_len(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, gen_msg_3_null)
{
	const uint8_t ctxt[] = { 0x40 };
	uint8_t msg[64] = { 0 };
	size_t msg_len = 0;

	int ret = gen_msg_3(NULL, ARRAY_SIZE(ctxt), msg, ARRAY_SIZE(msg),
			    &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_3(ctxt, 0, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_3(ctxt, ARRAY_SIZE(ctxt), NULL, ARRAY_SIZE(msg),
			&msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_3(ctxt, ARRAY_SIZE(ctxt), msg, 0, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_3(ctxt, ARRAY_SIZE(ctxt), msg, ARRAY_SIZE(msg), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, parse_msg_3_null)
{
	const uint8_t msg[] = { 0x40 };
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	int ret = parse_msg_3(NULL, ARRAY_SIZE(msg), &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_msg_3(msg, 0, &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_msg_3(msg, ARRAY_SIZE(msg), NULL, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_msg_3(msg, ARRAY_SIZE(msg), &ctxt, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, decrypt_ciphertext_3_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t iv[13] = { 0 };
	uint8_t aad[32] = { 0 };
	uint8_t ctxt[16] = { 0 };
	uint8_t ptxt[16] = { 0 };

	int ret = decrypt_ciphertext_3(NULL, iv, ARRAY_SIZE(iv), aad,
				       ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				       ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = decrypt_ciphertext_3(&ctx, NULL, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				   ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = decrypt_ciphertext_3(&ctx, iv, 0, aad, ARRAY_SIZE(aad), ctxt,
				   ARRAY_SIZE(ctxt), ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = decrypt_ciphertext_3(&ctx, iv, ARRAY_SIZE(iv), NULL,
				   ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				   ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = decrypt_ciphertext_3(&ctx, iv, ARRAY_SIZE(iv), aad, 0, ctxt,
				   ARRAY_SIZE(ctxt), ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = decrypt_ciphertext_3(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ctxt, 0, ptxt,
				   ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = decrypt_ciphertext_3(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				   NULL, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = decrypt_ciphertext_3(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				   ptxt, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, parse_plaintext_3_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	int ret = parse_plaintext_3(NULL, ptxt, ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_plaintext_3(&ctx, NULL, ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_plaintext_3(&ctx, ptxt, 0, &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_plaintext_3(&ctx, ptxt, ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, parse_plaintext_3_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret =
		parse_plaintext_3(&ctx, garbage, ARRAY_SIZE(garbage), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_message3)
{
	RUN_TEST_CASE(internals_message3, comp_th_3_null);
	RUN_TEST_CASE(internals_message3, comp_th_3_bad_state);
	RUN_TEST_CASE(internals_message3, comp_key_iv_aad_3_null);
	RUN_TEST_CASE(internals_message3, comp_key_iv_aad_3_bad_state);
	RUN_TEST_CASE(internals_message3, comp_plaintext_3_len_null);
	RUN_TEST_CASE(internals_message3, prepare_plaintext_3_null);
	RUN_TEST_CASE(internals_message3, comp_aad_3_len_null);
	RUN_TEST_CASE(internals_message3, gen_msg_3_null);
	RUN_TEST_CASE(internals_message3, parse_msg_3_null);
	RUN_TEST_CASE(internals_message3, decrypt_ciphertext_3_null);
	RUN_TEST_CASE(internals_message3, parse_plaintext_3_null);
	RUN_TEST_CASE(internals_message3, parse_plaintext_3_garbage);
}
