/**
 * \file    test_internals_message3.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_3.c internal functions.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_message3);

TEST_SETUP(internals_message3)
{
	psa_crypto_init();
	internals_keys = edhoc_cipher_suite_0_get_keys();
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_message3)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_message3, comp_th_3_null)
{
	int ret = comp_th_3(NULL, NULL, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, comp_th_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;

	uint8_t buf[512] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->th_len = 32;

	uint8_t ptxt[32] = { 0 };
	int ret = comp_th_3(&ctx, mc, ptxt, sizeof(ptxt));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals_message3, comp_key_iv_aad_3_null)
{
	uint8_t key[16], iv[13], aad[256];
	int ret = comp_key_iv_aad_3(NULL, key, 16, iv, 13, aad, 256);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, comp_key_iv_aad_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;
	ctx.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t key[16], iv[13], aad[256];
	int ret = comp_key_iv_aad_3(&ctx, key, 16, iv, 13, aad, 256);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals_message3, comp_plaintext_3_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_3_len(NULL, mc, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_3_len(&ctx, NULL, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_3_len(&ctx, mc, 0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_3_len(&ctx, mc, 8, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals_message3, prepare_plaintext_3_null)
{
	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256];
	size_t ptxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_3(NULL, sign, 8, ptxt, 256,
					      &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_3(mc, NULL, 8, ptxt, 256,
					      &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_3(mc, sign, 0, ptxt, 256,
					      &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_3(mc, sign, 8, NULL, 256,
					      &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_3(mc, sign, 8, ptxt, 0, &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_3(mc, sign, 8, ptxt, 256, NULL));
}

TEST(internals_message3, comp_aad_3_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_aad_3_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_aad_3_len(&ctx, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals_message3, gen_msg_3_null)
{
	uint8_t ctxt[] = { 0x40 };
	uint8_t msg[64];
	size_t msg_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_3(NULL, 1, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_3(ctxt, 0, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_3(ctxt, 1, NULL, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_3(ctxt, 1, msg, 0, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_3(ctxt, 1, msg, 64, NULL));
}

TEST(internals_message3, parse_msg_3_null)
{
	uint8_t msg[] = { 0x40 };
	const uint8_t *ctxt;
	size_t ctxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_3(NULL, 1, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_3(msg, 0, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_3(msg, 1, NULL, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_3(msg, 1, &ctxt, NULL));
}

TEST(internals_message3, decrypt_ciphertext_3_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t key[16] = { 0 }, iv[13] = { 0 }, aad[32] = { 0 };
	uint8_t ctxt[16] = { 0 }, ptxt[16] = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(NULL, key, 16, iv, 13, aad, 32,
					       ctxt, 16, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, NULL, 16, iv, 13, aad, 32,
					       ctxt, 16, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 0, iv, 13, aad, 32,
					       ctxt, 16, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 16, NULL, 13, aad, 32,
					       ctxt, 16, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 16, iv, 0, aad, 32,
					       ctxt, 16, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 16, iv, 13, NULL, 32,
					       ctxt, 16, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 16, iv, 13, aad, 0,
					       ctxt, 16, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 16, iv, 13, aad, 32,
					       ctxt, 0, ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 16, iv, 13, aad, 32,
					       ctxt, 16, NULL, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  decrypt_ciphertext_3(&ctx, key, 16, iv, 13, aad, 32,
					       ctxt, 16, ptxt, 0));
	edhoc_context_deinit(&ctx);
}

TEST(internals_message3, parse_plaintext_3_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_3(NULL, ptxt, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_3(&ctx, NULL, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_3(&ctx, ptxt, 0, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_3(&ctx, ptxt, 1, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals_message3, parse_plaintext_3_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret = parse_plaintext_3(&ctx, garbage, sizeof(garbage), &parsed);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
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
