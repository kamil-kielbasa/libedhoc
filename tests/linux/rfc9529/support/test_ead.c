/**
 * \file    test_ead.c
 * \author  Kamil Kielbasa
 * \brief   Shared EAD (External Authorization Data) test helpers implementation.
 *
 * \copyright Copyright (c) 2026
 */

/* Include files ----------------------------------------------------------- */

#include "test_ead.h"
#include "edhoc_macros_internal.h"

/* Static variables and constants ------------------------------------------ */

/* EAD token value arrays */
static const uint8_t ead_val_msg_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
static const uint8_t ead_val_msg_2[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
					 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
					 0x0c, 0x0d, 0x0e, 0x0f };
static const uint8_t ead_val_msg_3[] = {
	0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79, 0x5d, 0x39, 0x09, 0x71,
	0x8c, 0xdd, 0x05, 0xab, 0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
	0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd, 0x3c, 0xb2, 0x5f, 0x25,
	0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
	0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};
static const uint8_t ead_val_msg_4[] = { 0xff, 0xee, 0xdd, 0xcc,
					 0xbb, 0xaa, 0x00 };

/* The four distinct EAD tokens, indexed by \ref edhoc_message. */
static const struct edhoc_ead_token ead_tokens[] = {
	[EDHOC_MESSAGE_1] = { .label = 0,
			      .value = { .value = ead_val_msg_1,
					 .length = ARRAY_SIZE(ead_val_msg_1) } },
	[EDHOC_MESSAGE_2] = { .label = 24,
			      .value = { .value = ead_val_msg_2,
					 .length = ARRAY_SIZE(ead_val_msg_2) } },
	[EDHOC_MESSAGE_3] = { .label = 65535,
			      .value = { .value = ead_val_msg_3,
					 .length = ARRAY_SIZE(ead_val_msg_3) } },
	[EDHOC_MESSAGE_4] = { .label = -830,
			      .value = { .value = ead_val_msg_4,
					 .length = ARRAY_SIZE(ead_val_msg_4) } },
};

/* Multiple-token EAD: which tokens travel on each message, in which order. */
static const struct edhoc_ead_token *const ead_multiple_tokens_msg_1[] = {
	&ead_tokens[EDHOC_MESSAGE_1],
	&ead_tokens[EDHOC_MESSAGE_2],
	&ead_tokens[EDHOC_MESSAGE_3],
};

static const struct edhoc_ead_token *const ead_multiple_tokens_msg_2[] = {
	&ead_tokens[EDHOC_MESSAGE_3],
	&ead_tokens[EDHOC_MESSAGE_1],
};

static const struct edhoc_ead_token *const ead_multiple_tokens_msg_3[] = {
	&ead_tokens[EDHOC_MESSAGE_3],
	&ead_tokens[EDHOC_MESSAGE_2],
	&ead_tokens[EDHOC_MESSAGE_1],
};

static const struct edhoc_ead_token *const ead_multiple_tokens_msg_4[] = {
	&ead_tokens[EDHOC_MESSAGE_1],
	&ead_tokens[EDHOC_MESSAGE_4],
	&ead_tokens[EDHOC_MESSAGE_3],
};

int test_ead_compose_single(void *user_ctx,
			    const struct edhoc_call_context *call_context,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len)
{
	if (NULL == user_ctx || NULL == call_context || NULL == ead_token ||
	    0 == ead_token_size || NULL == ead_token_len)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	if (ARRAY_SIZE(ead_tokens) <= (size_t)call_context->message) {
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	ead_token[0] = ead_tokens[call_context->message];
	*ead_token_len = 1;

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->call_context = *call_context;
	ead_ctx->recv_tokens = 1;

	for (size_t i = 0; i < ead_ctx->recv_tokens; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_length = ead_token[i].value.length;
		memcpy(ead_ctx->token[i].value, ead_token[i].value.value,
		       ead_token[i].value.length);
	}

	return EDHOC_SUCCESS;
}

int test_ead_process_single(void *user_ctx,
			    const struct edhoc_call_context *call_context,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size)
{
	if (NULL == user_ctx || NULL == call_context || NULL == ead_token ||
	    0 == ead_token_size)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->call_context = *call_context;
	ead_ctx->recv_tokens = ead_token_size;

	for (size_t i = 0; i < ead_token_size; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_length = ead_token[i].value.length;
		memcpy(ead_ctx->token[i].value, ead_token[i].value.value,
		       ead_token[i].value.length);
	}

	return EDHOC_SUCCESS;
}

int test_ead_compose_multiple(void *user_ctx,
			      const struct edhoc_call_context *call_context,
			      struct edhoc_ead_token *ead_token,
			      size_t ead_token_size, size_t *ead_token_len)
{
	if (NULL == user_ctx || NULL == call_context || NULL == ead_token ||
	    0 == ead_token_size || NULL == ead_token_len)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	size_t len = 0;
	const struct edhoc_ead_token *const *tokens = NULL;

	switch (call_context->message) {
	case EDHOC_MESSAGE_1:
		tokens = ead_multiple_tokens_msg_1;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_1);
		break;
	case EDHOC_MESSAGE_2:
		tokens = ead_multiple_tokens_msg_2;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_2);
		break;
	case EDHOC_MESSAGE_3:
		tokens = ead_multiple_tokens_msg_3;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_3);
		break;
	case EDHOC_MESSAGE_4:
		tokens = ead_multiple_tokens_msg_4;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_4);
		break;
	default:
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	if (ead_token_size < len) {
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	*ead_token_len = len;

	for (size_t i = 0; i < len; ++i)
		ead_token[i] = *tokens[i];

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->call_context = *call_context;
	ead_ctx->recv_tokens = len;

	for (size_t i = 0; i < ead_ctx->recv_tokens; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_length = ead_token[i].value.length;
		memcpy(ead_ctx->token[i].value, ead_token[i].value.value,
		       ead_token[i].value.length);
	}

	return EDHOC_SUCCESS;
}

int test_ead_process_multiple(void *user_ctx,
			      const struct edhoc_call_context *call_context,
			      const struct edhoc_ead_token *ead_token,
			      size_t ead_token_size)
{
	if (NULL == user_ctx || NULL == call_context || NULL == ead_token ||
	    0 == ead_token_size)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->call_context = *call_context;
	ead_ctx->recv_tokens = ead_token_size;

	for (size_t i = 0; i < ead_token_size; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_length = ead_token[i].value.length;
		memcpy(ead_ctx->token[i].value, ead_token[i].value.value,
		       ead_token[i].value.length);
	}

	return EDHOC_SUCCESS;
}

int test_ead_compose_stub(void *user_ctx,
			  const struct edhoc_call_context *call_context,
			  struct edhoc_ead_token *ead_token,
			  size_t ead_token_size, size_t *ead_token_len)
{
	(void)user_ctx;
	(void)call_context;
	(void)ead_token;
	(void)ead_token_size;

	if (NULL == ead_token_len)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	*ead_token_len = 0;
	return EDHOC_SUCCESS;
}

int test_ead_process_stub(void *user_ctx,
			  const struct edhoc_call_context *call_context,
			  const struct edhoc_ead_token *ead_token,
			  size_t ead_token_size)
{
	(void)user_ctx;
	(void)call_context;
	(void)ead_token;
	(void)ead_token_size;

	return EDHOC_SUCCESS;
}

const struct edhoc_ead test_ead_stubs = {
	.compose = test_ead_compose_stub,
	.process = test_ead_process_stub,
};
