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

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_mac_internal.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */

/** \brief Credentials using a byte-string KID with a CBOR-encoded credential. */
extern const struct edhoc_credentials coverage_mock_creds_kid_bstr;

/** \brief Credentials using an x509 hash with a byte-string algorithm. */
extern const struct edhoc_credentials coverage_mock_creds_x5t_bstr;

/** \brief Credentials using an x509 hash with an integer algorithm. */
extern const struct edhoc_credentials coverage_mock_creds_x5t_int;

/** \brief Credentials using an x509 chain with multiple certificates. */
extern const struct edhoc_credentials coverage_mock_creds_x5chain_multi;

/** \brief EAD interface whose compose emits a single token carrying a value. */
extern const struct edhoc_ead coverage_mock_ead_with_value;

/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Reset failure injection; mocks start failing at the \p fail_at call
 *        (0 disables injection).
 */
void coverage_mock_reset(int fail_at);

/**
 * \brief Init a context and bind the mock crypto, platform, creds and EAD.
 *
 *        The Initiator and Responder variants differ only in the connection
 *        identifier, which RFC 9528: 3.3.3 requires to differ from the peer's
 *        for OSCORE to be derivable.
 */
int coverage_setup_mock_context_initiator(struct edhoc_context *ctx,
					  enum edhoc_method method);

int coverage_setup_mock_context_responder(struct edhoc_context *ctx,
					  enum edhoc_method method);

/** \brief As the functions above, but bind integer KID credentials. */
int coverage_setup_mock_context_kid_initiator(struct edhoc_context *ctx,
					      enum edhoc_method method);

int coverage_setup_mock_context_kid_responder(struct edhoc_context *ctx,
					      enum edhoc_method method);

/** \brief As the functions above, but use a byte-string connection ID. */
int coverage_setup_mock_context_bstr_cid_initiator(struct edhoc_context *ctx,
						   enum edhoc_method method);

int coverage_setup_mock_context_bstr_cid_responder(struct edhoc_context *ctx,
						   enum edhoc_method method);

/** \brief Compose message 1 on the initiator and process it on the responder. */
int coverage_do_msg1_flow(struct edhoc_context *init_ctx,
			  struct edhoc_context *resp_ctx, uint8_t *msg1,
			  size_t msg1_size, size_t *msg1_len);

/** \brief Run the message 1 flow, then compose message 2 on the responder. */
int coverage_do_full_msg2_flow(struct edhoc_context *init_ctx,
			       struct edhoc_context *resp_ctx, uint8_t *msg2,
			       size_t msg2_size, size_t *msg2_len);

/** \brief Run the message 2 flow, then process message 2 on the initiator. */
int coverage_do_mock_msg2_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx);

/** \brief Advance through message 2, then compose message 3 on the initiator. */
int coverage_do_mock_msg3_compose(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx, uint8_t *msg3,
				  size_t msg3_size, size_t *msg3_len);

/** \brief Compose message 3, then process it on the responder. */
int coverage_do_mock_msg3_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx);

/** \brief Advance through message 3, then compose and process message 4. */
int coverage_do_mock_msg4_process(struct edhoc_context *init_ctx,
				  struct edhoc_context *resp_ctx);

/** \brief EAD compose callback that emits an empty token set. */
int coverage_mock_ead_compose(void *user_ctx,
			      const struct edhoc_call_context *call_ctx,
			      struct edhoc_ead_token *ead_token,
			      size_t ead_token_size, size_t *ead_token_len);

/** \brief EAD process callback that accepts any token set. */
int coverage_mock_ead_process(void *user_ctx,
			      const struct edhoc_call_context *call_ctx,
			      const struct edhoc_ead_token *ead_token,
			      size_t ead_token_size);

/** \brief EAD compose callback that emits a single token. */
int coverage_mock_ead_compose_with_token(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	struct edhoc_ead_token *ead_token, size_t ead_token_size,
	size_t *ead_token_len);

/** \brief EAD process callback that always fails. */
int coverage_mock_ead_process_fail(void *user_ctx,
				   const struct edhoc_call_context *call_ctx,
				   const struct edhoc_ead_token *ead_token,
				   size_t ead_token_size);

/** \brief Credential fetch callback returning an invalid COSE header label. */
int coverage_mock_cred_select_local_invalid_label(
	void *user_ctx, const struct edhoc_call_context *call_context,
	struct edhoc_credential_selected *selected);

/** \brief Credential fetch callback returning an x509 chain with zero certs. */
int coverage_mock_cred_select_local_x509_zero_certs(
	void *user_ctx, const struct edhoc_call_context *call_context,
	struct edhoc_credential_selected *selected);

/** \brief Credential fetch callback that reports success without filling
 *         anything, leaving the structure as the library zeroed it. */
int coverage_mock_cred_select_local_untouched(
	void *user_ctx, const struct edhoc_call_context *call_context,
	struct edhoc_credential_selected *selected);

/** \brief Credential authenticate callback returning a fixed public key. */
int coverage_mock_cred_authenticate_peer(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted);

#endif /* COVERAGE_COMMON_H */
