/**
 * \file    test_ead.h
 * \author  Kamil Kielbasa
 * \brief   Shared EAD (External Authorization Data) test helpers.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
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
	size_t value_len;
};

/**
 * \brief Context structure for tracking EAD tokens across message exchanges.
 */
struct ead_context {
	enum edhoc_message msg;
	size_t recv_tokens;
	struct ead_token_buf token[MAX_NR_OF_EAD_TOKENS];
};

/* Shared EAD token test data */
extern const uint8_t ead_val_msg_1[10];
extern const uint8_t ead_val_msg_2[16];
extern const uint8_t ead_val_msg_3[120];
extern const uint8_t ead_val_msg_4[7];

extern const struct edhoc_ead_token ead_single_token_msg_1;
extern const struct edhoc_ead_token ead_single_token_msg_2;
extern const struct edhoc_ead_token ead_single_token_msg_3;
extern const struct edhoc_ead_token ead_single_token_msg_4;

extern const struct edhoc_ead_token ead_multiple_tokens_msg_1[];
extern const struct edhoc_ead_token ead_multiple_tokens_msg_2[];
extern const struct edhoc_ead_token ead_multiple_tokens_msg_3[];
extern const struct edhoc_ead_token ead_multiple_tokens_msg_4[];

#define EAD_MULTIPLE_TOKENS_MSG_1_LEN (3)
#define EAD_MULTIPLE_TOKENS_MSG_2_LEN (2)
#define EAD_MULTIPLE_TOKENS_MSG_3_LEN (3)
#define EAD_MULTIPLE_TOKENS_MSG_4_LEN (3)

/**
 * \brief EAD compose callback for single-token scenarios.
 */
int test_ead_compose_single(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *ead_token,
			    size_t ead_token_size, size_t *ead_token_len);

/**
 * \brief EAD process callback for single-token scenarios.
 */
int test_ead_process_single(void *user_ctx, enum edhoc_message msg,
			    const struct edhoc_ead_token *ead_token,
			    size_t ead_token_size);

/**
 * \brief EAD compose callback for multiple-token scenarios.
 */
int test_ead_compose_multiple(void *user_ctx, enum edhoc_message msg,
			      struct edhoc_ead_token *ead_token,
			      size_t ead_token_size, size_t *ead_token_len);

/**
 * \brief EAD process callback for multiple-token scenarios.
 */
int test_ead_process_multiple(void *user_ctx, enum edhoc_message msg,
			      const struct edhoc_ead_token *ead_token,
			      size_t ead_token_size);

/**
 * \brief Stub EAD compose callback that produces no tokens.
 */
int test_ead_compose_stub(void *user_ctx, enum edhoc_message msg,
			  struct edhoc_ead_token *ead_token,
			  size_t ead_token_size, size_t *ead_token_len);

/**
 * \brief Stub EAD process callback that accepts any tokens.
 */
int test_ead_process_stub(void *user_ctx, enum edhoc_message msg,
			  const struct edhoc_ead_token *ead_token,
			  size_t ead_token_size);

extern const struct edhoc_ead test_ead_stubs;

#endif /* TEST_EAD_H */
