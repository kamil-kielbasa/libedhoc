/**
 * \file    test_ead.h
 * \author  Kamil Kielbasa
 * \brief   Shared EAD (External Authorization Data) test helpers.
 *
 * \copyright Copyright (c) 2026
 */

#ifndef TEST_EAD_H
#define TEST_EAD_H

#include "test_common.h"

#define EAD_TOKEN_BUFFER_LEN (300)
#define MAX_NR_OF_EAD_TOKENS (3)

/**
 * \brief Buffer for storing a single EAD token during test verification.
 */
struct ead_token_buf {
	int32_t label;
	uint8_t value[EAD_TOKEN_BUFFER_LEN];
	size_t value_length;
};

/**
 * \brief Context structure for tracking EAD tokens across message exchanges.
 */
struct ead_context {
	struct edhoc_call_context call_context;
	size_t recv_tokens;
	struct ead_token_buf token[MAX_NR_OF_EAD_TOKENS];
};

/**
 * \brief EAD compose callback for single-token scenarios.
 */
int test_ead_compose_single(void *user_ctx,
			    const struct edhoc_call_context *call_context,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len);

/**
 * \brief EAD process callback for single-token scenarios.
 */
int test_ead_process_single(void *user_ctx,
			    const struct edhoc_call_context *call_context,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size);

/**
 * \brief EAD compose callback for multiple-token scenarios.
 */
int test_ead_compose_multiple(void *user_ctx,
			      const struct edhoc_call_context *call_context,
			      struct edhoc_ead_token *ead_token,
			      size_t ead_token_size, size_t *ead_token_len);

/**
 * \brief EAD process callback for multiple-token scenarios.
 */
int test_ead_process_multiple(void *user_ctx,
			      const struct edhoc_call_context *call_context,
			      const struct edhoc_ead_token *ead_token,
			      size_t ead_token_size);

/**
 * \brief Stub EAD compose callback that produces no tokens.
 */
int test_ead_compose_stub(void *user_ctx,
			  const struct edhoc_call_context *call_context,
			  struct edhoc_ead_token *ead_token,
			  size_t ead_token_size, size_t *ead_token_len);

/**
 * \brief Stub EAD process callback that accepts any tokens.
 */
int test_ead_process_stub(void *user_ctx,
			  const struct edhoc_call_context *call_context,
			  const struct edhoc_ead_token *ead_token,
			  size_t ead_token_size);

extern const struct edhoc_ead test_ead_stubs;

#endif /* TEST_EAD_H */
