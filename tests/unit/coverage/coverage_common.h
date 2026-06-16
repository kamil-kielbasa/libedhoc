/**
 * \file    coverage_common.h
 * \author  Kamil Kielbasa
 * \brief   Shared mock infrastructure for coverage unit tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef COVERAGE_COMMON_H
#define COVERAGE_COMMON_H

/* Include files ----------------------------------------------------------- */
#include "test_common.h"
#include "edhoc_common.h"
#include "edhoc_cipher_suite_2.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */

extern const struct edhoc_keys coverage_mock_keys;
extern const struct edhoc_crypto coverage_mock_crypto;
extern const struct edhoc_credentials coverage_mock_creds;
extern const struct edhoc_ead coverage_mock_ead;
extern const struct edhoc_credentials coverage_mock_creds_kid;
extern const struct edhoc_credentials coverage_mock_creds_kid_bstr;
extern const struct edhoc_credentials coverage_mock_creds_x5t_bstr;
extern const struct edhoc_credentials coverage_mock_creds_x5t_int;
extern const struct edhoc_credentials coverage_mock_creds_x5chain_multi;
extern const struct edhoc_credentials coverage_mock_creds_cose_any;
extern const struct edhoc_ead coverage_mock_ead_with_value;

/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

void coverage_mock_reset(int fail_at);
bool coverage_mock_should_fail(void);
void coverage_setup_mock_context(struct edhoc_context *ctx,
				 enum edhoc_method method);
void coverage_setup_mock_context_kid(struct edhoc_context *ctx,
				     enum edhoc_method method);
void coverage_setup_mock_context_bstr_cid(struct edhoc_context *ctx,
					  enum edhoc_method method);
int coverage_do_msg1_flow(struct edhoc_context *init_ctx,
			  struct edhoc_context *resp_ctx, uint8_t *msg1,
			  size_t msg1_size, size_t *msg1_len);
int coverage_do_full_msg2_flow(struct edhoc_context *init_ctx,
			       struct edhoc_context *resp_ctx, uint8_t *msg2,
			       size_t msg2_size, size_t *msg2_len);
int coverage_do_mock_msg2_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx);
int coverage_do_mock_msg3_compose(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx, uint8_t *msg3,
				  size_t msg3_size, size_t *msg3_len);
int coverage_do_mock_msg3_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx);
int coverage_mock_ead_compose(void *user_ctx, enum edhoc_message msg,
			      struct edhoc_ead_token *ead_token,
			      size_t ead_token_size, size_t *ead_token_len);
int coverage_mock_ead_process(void *user_ctx, enum edhoc_message msg,
			      const struct edhoc_ead_token *ead_token,
			      size_t ead_token_size);
int coverage_mock_ead_compose_with_token(void *user_ctx, enum edhoc_message msg,
					 struct edhoc_ead_token *ead_token,
					 size_t ead_token_size,
					 size_t *ead_token_len);
int coverage_mock_ead_process_fail(void *user_ctx, enum edhoc_message msg,
				   const struct edhoc_ead_token *ead_token,
				   size_t ead_token_size);
int coverage_mock_ead_compose_with_value(void *user_ctx, enum edhoc_message msg,
					 struct edhoc_ead_token *ead_token,
					 size_t ead_token_size,
					 size_t *ead_token_len);
int coverage_mock_ead_process_with_value(void *user_ctx, enum edhoc_message msg,
					 const struct edhoc_ead_token *ead_token,
					 size_t ead_token_size);
int coverage_mock_cred_fetch_invalid_label(void *user_ctx,
					   struct edhoc_auth_creds *auth_cred);
int coverage_mock_cred_fetch_x509_zero_certs(
	void *user_ctx, struct edhoc_auth_creds *auth_cred);
int coverage_mock_cred_verify(void *user_ctx,
			      struct edhoc_auth_creds *auth_cred,
			      const uint8_t **pub_key, size_t *pub_key_len);

#endif /* COVERAGE_COMMON_H */
