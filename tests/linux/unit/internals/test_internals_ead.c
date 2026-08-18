/**
 * \file    test_internals_ead.c
 * \author  Kamil Kielbasa
 * \brief   White-box unit tests for the EDHOC EAD module.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internals test support: */
#include "support/internals_common.h"

/* EDHOC headers: */
#include "edhoc_ead_internal.h"

/* CBOR headers: */
#include <backend_cbor_types.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const uint8_t ead_value[3] = { 0x01, 0x02, 0x03 };

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */

static int compose_ok(void *user_context,
		      const struct edhoc_call_context *call_context,
		      struct edhoc_ead_token *token, size_t token_size,
		      size_t *token_count)
{
	(void)user_context;
	(void)call_context;
	(void)token_size;

	token[0].label = 1;
	token[0].value.value = ead_value;
	token[0].value.length = sizeof(ead_value);
	token[1].label = 2;
	token[1].value.value = NULL;
	token[1].value.length = 0;
	*token_count = 2;

	return EDHOC_SUCCESS;
}

static int compose_fails(void *user_context,
			 const struct edhoc_call_context *call_context,
			 struct edhoc_ead_token *token, size_t token_size,
			 size_t *token_count)
{
	(void)user_context;
	(void)call_context;
	(void)token;
	(void)token_size;
	(void)token_count;

	return EDHOC_ERROR_GENERIC_ERROR;
}

static int compose_too_many(void *user_context,
			    const struct edhoc_call_context *call_context,
			    struct edhoc_ead_token *token, size_t token_size,
			    size_t *token_count)
{
	(void)user_context;
	(void)call_context;
	(void)token;
	(void)token_size;

	*token_count = CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS + 1;

	return EDHOC_SUCCESS;
}

static int compose_value_without_buffer(
	void *user_context, const struct edhoc_call_context *call_context,
	struct edhoc_ead_token *token, size_t token_size, size_t *token_count)
{
	(void)user_context;
	(void)call_context;
	(void)token_size;

	token[0].label = 1;
	token[0].value.value = NULL;
	token[0].value.length = sizeof(ead_value);
	*token_count = 1;

	return EDHOC_SUCCESS;
}

static int process_ok(void *user_context,
		      const struct edhoc_call_context *call_context,
		      const struct edhoc_ead_token *token, size_t token_count)
{
	(void)call_context;
	(void)token;
	(void)token_count;

	*(size_t *)user_context = token_count;

	return EDHOC_SUCCESS;
}

static int process_fails(void *user_context,
			 const struct edhoc_call_context *call_context,
			 const struct edhoc_ead_token *token,
			 size_t token_count)
{
	(void)user_context;
	(void)call_context;
	(void)token;
	(void)token_count;

	return EDHOC_ERROR_GENERIC_ERROR;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_ead);

TEST_SETUP(internals_ead)
{
}

TEST_TEAR_DOWN(internals_ead)
{
}

TEST(internals_ead, compose_null_context)
{
	const int ret = edhoc_ead_compose(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_ead, compose_without_callback)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_ead_compose(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0, ctx.ead.count);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, compose_accepts)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.interfaces.ead.compose = compose_ok;

	ret = edhoc_ead_compose(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(2, ctx.ead.count);
	TEST_ASSERT_EQUAL(1, ctx.ead.token[0].label);
	TEST_ASSERT_EQUAL(sizeof(ead_value), ctx.ead.token[0].value.length);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, compose_callback_failure)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.interfaces.ead.compose = compose_fails;

	ret = edhoc_ead_compose(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, compose_too_many_tokens)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.interfaces.ead.compose = compose_too_many;

	ret = edhoc_ead_compose(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, compose_value_without_buffer)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.interfaces.ead.compose = compose_value_without_buffer;

	ret = edhoc_ead_compose(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, process_null_context)
{
	const int ret = edhoc_ead_process(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_ead, process_without_tokens)
{
	struct edhoc_context ctx = { 0 };
	size_t seen = SIZE_MAX;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.interfaces.ead.process = process_ok;
	ctx.user_context = &seen;

	ret = edhoc_ead_process(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(SIZE_MAX, seen);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, process_hands_tokens_over)
{
	struct edhoc_context ctx = { 0 };
	size_t seen = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.interfaces.ead.process = process_ok;
	ctx.user_context = &seen;
	ctx.ead.count = 1;
	ctx.ead.token[0].label = 1;
	ctx.ead.token[0].value.value = ead_value;
	ctx.ead.token[0].value.length = sizeof(ead_value);

	ret = edhoc_ead_process(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(1, seen);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, process_callback_failure)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.interfaces.ead.process = process_fails;
	ctx.ead.count = 1;
	ctx.ead.token[0].label = 1;

	ret = edhoc_ead_process(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, encoded_length_null_args)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_ead_encoded_length(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_ead_encoded_length(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, encoded_length_no_tokens)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.ead.count = 0;

	ret = edhoc_ead_encoded_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, encoded_length_with_tokens)
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

	ret = edhoc_ead_encoded_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Two one-byte labels, two one-byte bstr heads and the values. */
	TEST_ASSERT_EQUAL(4 + sizeof(val0) + sizeof(val1), len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, tokens_encode_null_args)
{
	struct edhoc_context ctx = { 0 };
	struct ead tokens = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_ead_tokens_encode(NULL, &tokens);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_ead_tokens_encode(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, tokens_encode_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	struct ead tokens = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.ead.count = ARRAY_SIZE(tokens.ead) + 1;

	ret = edhoc_ead_tokens_encode(&ctx, &tokens);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, tokens_round_trip)
{
	struct edhoc_context ctx = { 0 };
	struct ead tokens = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.ead.count = 2;
	ctx.ead.token[0].label = 7;
	ctx.ead.token[0].value.value = ead_value;
	ctx.ead.token[0].value.length = sizeof(ead_value);
	ctx.ead.token[1].label = 8;
	ctx.ead.token[1].value.value = NULL;
	ctx.ead.token[1].value.length = 0;

	ret = edhoc_ead_tokens_encode(&ctx, &tokens);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(2, tokens.ead_count);
	TEST_ASSERT_TRUE(tokens.ead[0].ead_x_ead_value_present);
	TEST_ASSERT_FALSE(tokens.ead[1].ead_x_ead_value_present);

	memset(&ctx.ead, 0, sizeof(ctx.ead));

	ret = edhoc_ead_tokens_decode(&ctx, &tokens);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(2, ctx.ead.count);
	TEST_ASSERT_EQUAL(7, ctx.ead.token[0].label);
	TEST_ASSERT_EQUAL_PTR(ead_value, ctx.ead.token[0].value.value);
	TEST_ASSERT_EQUAL(sizeof(ead_value), ctx.ead.token[0].value.length);
	TEST_ASSERT_EQUAL(8, ctx.ead.token[1].label);
	TEST_ASSERT_NULL(ctx.ead.token[1].value.value);
	TEST_ASSERT_EQUAL(0, ctx.ead.token[1].value.length);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, tokens_decode_null_args)
{
	struct edhoc_context ctx = { 0 };
	struct ead tokens = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_ead_tokens_decode(NULL, &tokens);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_ead_tokens_decode(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_ead, tokens_decode_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	struct ead tokens = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	tokens.ead_count = EDHOC_EAD_CAPACITY + 1;

	ret = edhoc_ead_tokens_decode(&ctx, &tokens);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_ead)
{
	RUN_TEST_CASE(internals_ead, compose_null_context);
	RUN_TEST_CASE(internals_ead, compose_without_callback);
	RUN_TEST_CASE(internals_ead, compose_accepts);
	RUN_TEST_CASE(internals_ead, compose_callback_failure);
	RUN_TEST_CASE(internals_ead, compose_too_many_tokens);
	RUN_TEST_CASE(internals_ead, compose_value_without_buffer);

	RUN_TEST_CASE(internals_ead, process_null_context);
	RUN_TEST_CASE(internals_ead, process_without_tokens);
	RUN_TEST_CASE(internals_ead, process_hands_tokens_over);
	RUN_TEST_CASE(internals_ead, process_callback_failure);

	RUN_TEST_CASE(internals_ead, encoded_length_null_args);
	RUN_TEST_CASE(internals_ead, encoded_length_no_tokens);
	RUN_TEST_CASE(internals_ead, encoded_length_with_tokens);

	RUN_TEST_CASE(internals_ead, tokens_encode_null_args);
	RUN_TEST_CASE(internals_ead, tokens_encode_buffer_too_small);
	RUN_TEST_CASE(internals_ead, tokens_round_trip);
	RUN_TEST_CASE(internals_ead, tokens_decode_null_args);
	RUN_TEST_CASE(internals_ead, tokens_decode_buffer_too_small);
}
