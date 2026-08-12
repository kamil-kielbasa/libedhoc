/**
 * \file    test_internals_message3.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_classic_message_3.c internal functions.
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

TEST(internals_message3, comp_key_iv_aad_3_null)
{
	uint8_t iv[13] = { 0 };
	uint8_t aad[256] = { 0 };
	const uint8_t th[32] = { 0 };
	int ret = edhoc_cipher_derive(NULL, th, ARRAY_SIZE(th), iv,
				      ARRAY_SIZE(iv), aad, ARRAY_SIZE(aad));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, comp_key_iv_aad_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t iv[13] = { 0 };
	uint8_t aad[256] = { 0 };
	const uint8_t th[32] = { 0 };
	int ret = edhoc_cipher_derive(&ctx, th, ARRAY_SIZE(th), iv,
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
	struct mac_context mc_storage = {
		.buf = buf,
		.buf_len = sizeof(buf),
	};
	struct mac_context *mc = &mc_storage;

	struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_CLASSIC_3,
		.mac_context = mc,
		.signature_length = 8,
	};
	size_t len = 0;

	int ret = edhoc_plaintext_length(NULL, &input, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_length(&ctx, NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_length(&ctx, &input, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	input.mac_context = NULL;
	ret = edhoc_plaintext_length(&ctx, &input, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	input.mac_context = mc;
	input.signature_length = 0;
	ret = edhoc_plaintext_length(&ctx, &input, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, plaintext_compose_3_null)
{
	struct edhoc_context ctx = { 0 };
	uint8_t buf[256] = { 0 };
	struct mac_context mc_storage = {
		.buf = buf,
		.buf_len = sizeof(buf),
	};
	struct mac_context *mc = &mc_storage;

	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256] = { 0 };
	size_t ptxt_len = 0;

	struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_CLASSIC_3,
		.mac_context = mc,
		.signature = sign,
		.signature_length = ARRAY_SIZE(sign),
	};

	int ret = edhoc_plaintext_compose(NULL, &input, ptxt, ARRAY_SIZE(ptxt),
					  &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_compose(&ctx, NULL, ptxt, ARRAY_SIZE(ptxt),
				      &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_compose(&ctx, &input, NULL, ARRAY_SIZE(ptxt),
				      &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_compose(&ctx, &input, ptxt, 0, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_compose(&ctx, &input, ptxt, ARRAY_SIZE(ptxt),
				      NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	input.signature = NULL;
	ret = edhoc_plaintext_compose(&ctx, &input, ptxt, ARRAY_SIZE(ptxt),
				      &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	input.signature = sign;
	input.signature_length = 0;
	ret = edhoc_plaintext_compose(&ctx, &input, ptxt, ARRAY_SIZE(ptxt),
				      &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, comp_aad_3_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	size_t len = 0;

	int ret = edhoc_cipher_aad_length(NULL, ctx.state.th.length, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_aad_length(&ctx, ctx.state.th.length, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, decrypt_ciphertext_3_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t iv[13] = { 0 };
	uint8_t aad[32] = { 0 };
	uint8_t ctxt[16] = { 0 };
	uint8_t ptxt[16] = { 0 };

	int ret = edhoc_cipher_decrypt(NULL, iv, ARRAY_SIZE(iv), aad,
				       ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				       ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_decrypt(&ctx, NULL, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				   ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_decrypt(&ctx, iv, 0, aad, ARRAY_SIZE(aad), ctxt,
				   ARRAY_SIZE(ctxt), ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_decrypt(&ctx, iv, ARRAY_SIZE(iv), NULL,
				   ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				   ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_decrypt(&ctx, iv, ARRAY_SIZE(iv), aad, 0, ctxt,
				   ARRAY_SIZE(ctxt), ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_decrypt(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ctxt, 0, ptxt,
				   ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_decrypt(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				   NULL, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, parse_plaintext_3_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.message = EDHOC_MESSAGE_3;

	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	int ret = edhoc_plaintext_parse(NULL, EDHOC_PLAINTEXT_CLASSIC_3, ptxt,
					ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_3, NULL,
				    ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_3, ptxt, 0,
				    &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_3, ptxt,
				    ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, parse_plaintext_3_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.message = EDHOC_MESSAGE_3;

	const uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_3,
					garbage, ARRAY_SIZE(garbage), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, compose_ciphertext_3_null)
{
	uint8_t ctxt[16] = { 0 };
	uint8_t msg[32] = { 0 };
	size_t msg_len = 0;

	int ret = compose_ciphertext_3(NULL, ARRAY_SIZE(ctxt), msg,
				       ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_3(ctxt, 0, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_3(ctxt, ARRAY_SIZE(ctxt), NULL,
				   ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_3(ctxt, ARRAY_SIZE(ctxt), msg, 0, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_3(ctxt, ARRAY_SIZE(ctxt), msg, ARRAY_SIZE(msg),
				   NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, parse_ciphertext_3_null)
{
	uint8_t msg[32] = { 0 };
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	int ret = parse_ciphertext_3(NULL, ARRAY_SIZE(msg), &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_ciphertext_3(msg, 0, &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_ciphertext_3(msg, ARRAY_SIZE(msg), NULL, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_ciphertext_3(msg, ARRAY_SIZE(msg), &ctxt, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message3, psk_plaintext_3a_round_trip)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	/* draft-ietf-lake-edhoc-psk: B.3 - PLAINTEXT_3A is the compact
	 * ID_CRED_PSK followed by CIPHERTEXT_3B as a byte string. */
	static const uint8_t id_cred_psk[] = { 0x42, 0x00, 0x10 };
	static const uint8_t ciphertext_3b[] = { 0xb1, 0x74, 0xed, 0xba,
						 0xa0, 0x64, 0x73, 0x82 };

	const struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_PSK_3A,
		.id_cred_psk = id_cred_psk,
		.id_cred_psk_length = ARRAY_SIZE(id_cred_psk),
		.ciphertext_3b = ciphertext_3b,
		.ciphertext_3b_length = ARRAY_SIZE(ciphertext_3b),
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_length(&ctx, &input, &len));

	uint8_t ptxt[32] = { 0 };
	size_t ptxt_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_compose(&ctx, &input, ptxt,
						  ARRAY_SIZE(ptxt), &ptxt_len));
	TEST_ASSERT_EQUAL_size_t(len, ptxt_len);

	struct plaintext parsed = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_3A,
						ptxt, ptxt_len, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(ciphertext_3b),
				 parsed.ciphertext_3b.length);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(ciphertext_3b, parsed.ciphertext_3b.value,
				     parsed.ciphertext_3b.length);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message3, psk_plaintext_3a_rejects)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	static const uint8_t id_cred_psk[] = { 0x42, 0x00, 0x10 };
	static const uint8_t ciphertext_3b[] = { 0xb1, 0x74 };

	struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_PSK_3A,
		.id_cred_psk = id_cred_psk,
		.id_cred_psk_length = ARRAY_SIZE(id_cred_psk),
		.ciphertext_3b = ciphertext_3b,
		.ciphertext_3b_length = ARRAY_SIZE(ciphertext_3b),
	};

	uint8_t ptxt[32] = { 0 };
	size_t ptxt_len = 0;
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL,
			  edhoc_plaintext_compose(&ctx, &input, ptxt, 2,
						  &ptxt_len));

	input.id_cred_psk = NULL;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_plaintext_length(&ctx, &input, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_plaintext_compose(&ctx, &input, ptxt,
						  ARRAY_SIZE(ptxt), &ptxt_len));

	input.id_cred_psk = id_cred_psk;
	input.ciphertext_3b = NULL;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_plaintext_length(&ctx, &input, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_plaintext_compose(&ctx, &input, ptxt,
						  ARRAY_SIZE(ptxt), &ptxt_len));

	static const uint8_t garbage[] = { 0xff, 0xff };
	struct plaintext parsed = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_3A,
						garbage, ARRAY_SIZE(garbage),
						&parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_3A,
						garbage, ARRAY_SIZE(garbage),
						NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message3, psk_plaintext_3a_id_cred_forms)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	struct plaintext parsed = { 0 };

	/* A 'kid' in the CBOR integer form. */
	static const uint8_t int_form[] = { 0x2b, 0x41, 0x00 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_3A,
						int_form, ARRAY_SIZE(int_form),
						&parsed));
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID,
			  parsed.peer_credential_id.label);

	/* RFC 9528: 3.5.3.2 - a 'kid' in map form is rejected. */
	static const uint8_t map_form[] = { 0xa1, 0x04, 0x41, 0x2b, 0x41, 0x00 };

	TEST_ASSERT_NOT_EQUAL(
		EDHOC_SUCCESS,
		edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_3A, map_form,
				      ARRAY_SIZE(map_form), &parsed));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message3, psk_plaintext_3b_empty)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_PSK_3B,
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_length(&ctx, &input, &len));
	TEST_ASSERT_EQUAL_size_t(0, len);

	uint8_t ptxt[8] = { 0 };
	size_t ptxt_len = 1;

	/* draft-ietf-lake-edhoc-psk: 5.3.2 - PLAINTEXT_3B is empty without
	 * EAD_3. */
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_compose(&ctx, &input, ptxt,
						  ARRAY_SIZE(ptxt), &ptxt_len));
	TEST_ASSERT_EQUAL_size_t(0, ptxt_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_3B,
						ptxt, ptxt_len, NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message3, plaintext_unknown_id_rejected)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const struct edhoc_plaintext_input input = {
		.id = (enum edhoc_plaintext_id)99,
	};

	uint8_t ptxt[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_plaintext_length(&ctx, &input, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_plaintext_compose(&ctx, &input, ptxt,
						  ARRAY_SIZE(ptxt), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_plaintext_parse(&ctx,
						(enum edhoc_plaintext_id)99,
						ptxt, ARRAY_SIZE(ptxt), NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message3, comp_key_iv_aad_3_state_mismatch)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_4;

	uint8_t iv[13] = { 0 };
	uint8_t aad[256] = { 0 };
	const uint8_t th[32] = { 0 };

	/* The transcript hash must already be TH_3. */
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	int ret = edhoc_cipher_derive(&ctx, th, ARRAY_SIZE(th), iv,
				      ARRAY_SIZE(iv), aad, ARRAY_SIZE(aad));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	/* draft-ietf-lake-edhoc-psk: 4 - K_3 comes from PRK_4e3m. */
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	ret = edhoc_cipher_derive(&ctx, th, ARRAY_SIZE(th), iv, ARRAY_SIZE(iv),
				  aad, ARRAY_SIZE(aad));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, encrypt_ciphertext_3_null)
{
	uint8_t iv[13] = { 0 };
	uint8_t aad[64] = { 0 };
	uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	size_t len = 0;

	int ret = edhoc_cipher_encrypt(NULL, iv, ARRAY_SIZE(iv), aad,
				       ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				       ctxt, ARRAY_SIZE(ctxt), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ret = edhoc_cipher_encrypt(&ctx, NULL, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				   ctxt, ARRAY_SIZE(ctxt), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_encrypt(&ctx, iv, ARRAY_SIZE(iv), NULL,
				   ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				   ctxt, ARRAY_SIZE(ctxt), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_encrypt(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), NULL, ARRAY_SIZE(ptxt),
				   ctxt, ARRAY_SIZE(ctxt), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_encrypt(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				   ctxt, ARRAY_SIZE(ctxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* Messages 1 and 2 carry no AEAD protected payload. */
	ctx.state.message = EDHOC_MESSAGE_1;

	ret = edhoc_cipher_encrypt(&ctx, iv, ARRAY_SIZE(iv), aad,
				   ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				   ctxt, ARRAY_SIZE(ctxt), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, decrypt_ciphertext_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.message = EDHOC_MESSAGE_2;

	uint8_t iv[13] = { 0 };
	uint8_t aad[64] = { 0 };
	uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[16] = { 0 };

	int ret = edhoc_cipher_decrypt(&ctx, iv, ARRAY_SIZE(iv), aad,
				       ARRAY_SIZE(aad), ctxt, ARRAY_SIZE(ctxt),
				       ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message3, keystream_3a_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t keystream[16] = { 0 };

	int ret =
		edhoc_cipher_keystream(NULL, keystream, ARRAY_SIZE(keystream));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_keystream(&ctx, NULL, ARRAY_SIZE(keystream));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_keystream(&ctx, keystream, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* draft-ietf-lake-edhoc-psk: 5.3 - only method 4 keystreams message
	 * 3. */
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	ret = edhoc_cipher_keystream(&ctx, keystream, ARRAY_SIZE(keystream));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	/* Method 4, but the transcript hash is not yet TH_3. */
	ctx.negotiation.selected_method = EDHOC_METHOD_4;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	ret = edhoc_cipher_keystream(&ctx, keystream, ARRAY_SIZE(keystream));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_message3)
{
	RUN_TEST_CASE(internals_message3, compose_ciphertext_3_null);
	RUN_TEST_CASE(internals_message3, parse_ciphertext_3_null);
	RUN_TEST_CASE(internals_message3, comp_key_iv_aad_3_null);
	RUN_TEST_CASE(internals_message3, comp_key_iv_aad_3_bad_state);
	RUN_TEST_CASE(internals_message3, comp_plaintext_3_len_null);
	RUN_TEST_CASE(internals_message3, plaintext_compose_3_null);
	RUN_TEST_CASE(internals_message3, comp_aad_3_len_null);
	RUN_TEST_CASE(internals_message3, decrypt_ciphertext_3_null);
	RUN_TEST_CASE(internals_message3, parse_plaintext_3_null);
	RUN_TEST_CASE(internals_message3, parse_plaintext_3_garbage);
	RUN_TEST_CASE(internals_message3, psk_plaintext_3a_round_trip);
	RUN_TEST_CASE(internals_message3, psk_plaintext_3a_rejects);
	RUN_TEST_CASE(internals_message3, psk_plaintext_3a_id_cred_forms);
	RUN_TEST_CASE(internals_message3, psk_plaintext_3b_empty);
	RUN_TEST_CASE(internals_message3, plaintext_unknown_id_rejected);
	RUN_TEST_CASE(internals_message3, comp_key_iv_aad_3_state_mismatch);
	RUN_TEST_CASE(internals_message3, encrypt_ciphertext_3_null);
	RUN_TEST_CASE(internals_message3, decrypt_ciphertext_3_bad_state);
	RUN_TEST_CASE(internals_message3, keystream_3a_bad_state);
}
