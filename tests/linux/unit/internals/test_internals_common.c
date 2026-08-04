/**
 * \file    test_internals_common.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for common internal length and PRK helpers.
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

TEST_GROUP(internals_common);

TEST_SETUP(internals_common)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_common)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_common, connection_id_length_compact)
{
	const struct connection_id cid = { .value = { 0x05 }, .length = 1 };

	TEST_ASSERT_EQUAL_size_t(1, edhoc_connection_id_encoded_length(&cid));
}

TEST(internals_common, connection_id_length_byte_string)
{
	const struct connection_id cid = { .value = { 0xff }, .length = 1 };

	TEST_ASSERT_EQUAL_size_t(2, edhoc_connection_id_encoded_length(&cid));
}

TEST(internals_common, connection_id_length_null)
{
	TEST_ASSERT_EQUAL_size_t(0, edhoc_connection_id_encoded_length(NULL));
}

TEST(internals_common, connection_id_encode_follows_rfc)
{
	/* RFC 9528: 3.3.2 - h'21' travels as the CBOR integer -2, h'18' does
	 * not fit the compact form and stays a byte string. */
	const struct connection_id compact = { .value = { 0x21 }, .length = 1 };
	const struct connection_id wide = { .value = { 0x18 }, .length = 1 };
	const struct connection_id empty = { .length = 0 };

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_connection_id_encode(&compact, buffer,
						     ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(0x21, buffer[0]);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_connection_id_encode(&wide, buffer,
						     ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(2, len);
	TEST_ASSERT_EQUAL_HEX8(0x41, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8(0x18, buffer[1]);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_connection_id_encode(&empty, buffer,
						     ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(0x40, buffer[0]);
}

TEST(internals_common, connection_id_encode_null_args)
{
	const struct connection_id cid = { .value = { 0x05 }, .length = 1 };
	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_connection_id_encode(NULL, buffer,
						     ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_connection_id_encode(&cid, NULL,
						     ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_connection_id_encode(&cid, buffer, 0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_connection_id_encode(&cid, buffer,
						     ARRAY_SIZE(buffer), NULL));
}

TEST(internals_common, connection_id_from_int_recovers_the_byte)
{
	struct connection_id cid = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_connection_id_from_int(-12, &cid));
	TEST_ASSERT_EQUAL_size_t(1, cid.length);
	TEST_ASSERT_EQUAL_HEX8(0x2b, cid.value[0]);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_connection_id_from_int(23, &cid));
	TEST_ASSERT_EQUAL_HEX8(0x17, cid.value[0]);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_connection_id_from_int(-24, &cid));
	TEST_ASSERT_EQUAL_HEX8(0x37, cid.value[0]);
}

TEST(internals_common, connection_id_from_int_rejects_wide)
{
	struct connection_id cid = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_connection_id_from_int(24, &cid));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_connection_id_from_int(-25, &cid));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_connection_id_from_int(0, NULL));
}

TEST(internals_common, connection_id_from_bstr)
{
	const uint8_t value[] = { 0xaa, 0xbb };
	struct connection_id cid = { 0 };

	TEST_ASSERT_EQUAL(
		EDHOC_SUCCESS,
		edhoc_connection_id_from_bstr(value, ARRAY_SIZE(value), &cid));
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(value), cid.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(value, cid.value, cid.length);

	/* RFC 9528: 3.3 allows the empty identifier. */
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_connection_id_from_bstr(NULL, 0, &cid));
	TEST_ASSERT_EQUAL_size_t(0, cid.length);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL,
			  edhoc_connection_id_from_bstr(
				  value, CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID + 1,
				  &cid));
	TEST_ASSERT_EQUAL(
		EDHOC_ERROR_INVALID_ARGUMENT,
		edhoc_connection_id_from_bstr(value, ARRAY_SIZE(value), NULL));
}

TEST(internals_common, comp_th_len_success)
{
	size_t len = 0;

	int ret = comp_th_len(32, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(34, len);
}

TEST(internals_common, comp_th_len_zero)
{
	size_t len = 0;

	int ret = comp_th_len(0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_ead_len_no_tokens)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.ead.count = 0;

	ret = comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_ead_len_with_tokens)
{
	uint8_t val0[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t val1[2] = { 0xAA, 0xBB };
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.ead.count = 2;
	ctx.ead.token[0].label = 1;
	ctx.ead.token[0].value.value = val0;
	ctx.ead.token[0].value.length = sizeof(val0);
	ctx.ead.token[1].label = 2;
	ctx.ead.token[1].value.value = val1;
	ctx.ead.token[1].value.length = sizeof(val1);

	ret = comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, validate_ead_composed_accepts)
{
	static const uint8_t val[3] = { 0x01, 0x02, 0x03 };
	const struct edhoc_ead_token tokens[] = {
		{ .label = 1,
		  .value = { .value = val, .length = sizeof(val) } },
		{ .label = 2, .value = { .value = NULL, .length = 0 } },
	};

	const int ret = edhoc_validate_ead_composed(tokens, ARRAY_SIZE(tokens));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, validate_ead_composed_no_tokens)
{
	const int ret = edhoc_validate_ead_composed(NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, validate_ead_composed_null_tokens)
{
	const int ret = edhoc_validate_ead_composed(NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, validate_ead_composed_value_without_buffer)
{
	const struct edhoc_ead_token tokens[] = {
		{ .label = 1, .value = { .value = NULL, .length = 4 } },
	};

	const int ret = edhoc_validate_ead_composed(tokens, ARRAY_SIZE(tokens));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);
}

TEST(internals_common, comp_ead_len_null_args)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = comp_ead_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_ead_len(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_2e_bad_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	int ret = comp_prk_2e(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_2e_null_args)
{
	int ret = comp_prk_2e(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_prk_3e2m_method_0)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;

	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_3e2m(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_method_1)
{
	uint8_t prk_2e[32] = { 0 };
	uint8_t dh_priv[32] = { 0 };
	uint8_t pub_key[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk_2e[i] = (uint8_t)(i + 0x20);
		dh_priv[i] = (uint8_t)(i + 0x40);
		pub_key[i] = (uint8_t)(i + 0x80);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_2E, prk_2e,
			     sizeof(prk_2e));

	/* Responder G_RX = key_agreement(its static key, peer ephemeral G_X). */
	internals_make_ecdh_peer_pub(ctx.ephemeral.peer.value,
				     sizeof(ctx.ephemeral.peer.value),
				     &ctx.ephemeral.peer.length);

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	internals_inject_ecdh_key(key_id, dh_priv, sizeof(dh_priv));

	int ret = comp_prk_3e2m(&ctx, key_id, pub_key, sizeof(pub_key));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_method_max)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = (enum edhoc_method)4;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;

	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_3e2m(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_3e2m(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_null_args)
{
	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_3e2m(NULL, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_prk_4e3m_method_0)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;

	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_4e3m(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_method_2)
{
	uint8_t prk_3e2m[32] = { 0 };
	uint8_t dh_priv[32] = { 0 };
	uint8_t pub_key[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk_3e2m[i] = (uint8_t)(i + 0x20);
		dh_priv[i] = (uint8_t)(i + 0x40);
		pub_key[i] = (uint8_t)(i + 0x80);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_3E2M, prk_3e2m,
			     sizeof(prk_3e2m));

	/* Initiator G_IY = key_agreement(its static key, peer ephemeral G_Y). */
	internals_make_ecdh_peer_pub(ctx.ephemeral.peer.value,
				     sizeof(ctx.ephemeral.peer.value),
				     &ctx.ephemeral.peer.length);

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	internals_inject_ecdh_key(key_id, dh_priv, sizeof(dh_priv));

	int ret = comp_prk_4e3m(&ctx, key_id, pub_key, sizeof(pub_key));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_method_max)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = (enum edhoc_method)4;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;

	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_4e3m(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_3;

	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_4e3m(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_null_args)
{
	static const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	int ret = comp_prk_4e3m(NULL, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_prk_out_success)
{
	uint8_t prk[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk[i] = (uint8_t)(i + 0x20);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_4E3M, prk, sizeof(prk));

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_out_bad_th_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_out_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.length = 32;

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_out_null_args)
{
	int ret = compute_prk_out(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_new_prk_out_success)
{
	uint8_t prk[32] = { 0 };
	uint8_t entropy[16] = { 0xBB };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk[i] = (uint8_t)(i + 0x20);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_4E3M, prk, sizeof(prk));

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_new_prk_out_bad_state)
{
	uint8_t entropy[16] = { 0xAA };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	int ret = compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_new_prk_out_null_args)
{
	uint8_t entropy[16] = { 0 };

	int ret = compute_new_prk_out(NULL, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_prk_exporter_success)
{
	uint8_t prk[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk[i] = (uint8_t)(i + 0x20);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_4E3M, prk, sizeof(prk));

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = compute_prk_exporter(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(
		edhoc_key_slot_present(&ctx, EDHOC_KEY_SLOT_PRK_EXPORTER));

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_exporter_bad_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	int ret = compute_prk_exporter(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_exporter_null_args)
{
	int ret = compute_prk_exporter(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_salt_3e2m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_3e2m_null_args)
{
	uint8_t salt[32] = { 0 };

	int ret = comp_salt_3e2m(NULL, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* comp_salt_4e3m ---------------------------------------------------------- */

TEST(internals_common, comp_salt_4e3m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_4e3m_null_args)
{
	uint8_t salt[32] = { 0 };

	int ret = comp_salt_4e3m(NULL, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(internals_common)
{
	/* connection identifier */
	RUN_TEST_CASE(internals_common, connection_id_length_compact);
	RUN_TEST_CASE(internals_common, connection_id_length_byte_string);
	RUN_TEST_CASE(internals_common, connection_id_length_null);
	RUN_TEST_CASE(internals_common, connection_id_encode_follows_rfc);
	RUN_TEST_CASE(internals_common, connection_id_encode_null_args);
	RUN_TEST_CASE(internals_common,
		      connection_id_from_int_recovers_the_byte);
	RUN_TEST_CASE(internals_common, connection_id_from_int_rejects_wide);
	RUN_TEST_CASE(internals_common, connection_id_from_bstr);

	/* comp_th_len */
	RUN_TEST_CASE(internals_common, comp_th_len_success);
	RUN_TEST_CASE(internals_common, comp_th_len_zero);

	/* comp_ead_len */
	RUN_TEST_CASE(internals_common, comp_ead_len_no_tokens);
	RUN_TEST_CASE(internals_common, comp_ead_len_with_tokens);
	RUN_TEST_CASE(internals_common, validate_ead_composed_accepts);
	RUN_TEST_CASE(internals_common, validate_ead_composed_no_tokens);
	RUN_TEST_CASE(internals_common, validate_ead_composed_null_tokens);
	RUN_TEST_CASE(internals_common,
		      validate_ead_composed_value_without_buffer);
	RUN_TEST_CASE(internals_common, comp_ead_len_null_args);

	/* comp_prk_2e */
	RUN_TEST_CASE(internals_common, comp_prk_2e_bad_state);
	RUN_TEST_CASE(internals_common, comp_prk_2e_null_args);

	/* comp_prk_3e2m */
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_0);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_1);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_max);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_null_args);

	/* comp_prk_4e3m */
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_0);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_2);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_max);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_null_args);

	/* compute_prk_out */
	RUN_TEST_CASE(internals_common, compute_prk_out_success);
	RUN_TEST_CASE(internals_common, compute_prk_out_bad_th_state);
	RUN_TEST_CASE(internals_common, compute_prk_out_bad_prk_state);
	RUN_TEST_CASE(internals_common, compute_prk_out_null_args);

	/* compute_new_prk_out */
	RUN_TEST_CASE(internals_common, compute_new_prk_out_success);
	RUN_TEST_CASE(internals_common, compute_new_prk_out_bad_state);
	RUN_TEST_CASE(internals_common, compute_new_prk_out_null_args);

	/* compute_prk_exporter */
	RUN_TEST_CASE(internals_common, compute_prk_exporter_success);
	RUN_TEST_CASE(internals_common, compute_prk_exporter_bad_state);
	RUN_TEST_CASE(internals_common, compute_prk_exporter_null_args);

	/* comp_salt_3e2m */
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_bad_th_state);
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_null_args);

	/* comp_salt_4e3m */
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_bad_th_state);
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_null_args);
}
