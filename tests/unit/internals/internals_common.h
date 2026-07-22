/**
 * \file    internals_common.h
 * \author  Kamil Kielbasa
 * \brief   Shared fixtures and extern declarations for internals unit tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef INTERNALS_COMMON_H
#define INTERNALS_COMMON_H

/* Include files ----------------------------------------------------------- */
#include "test_common.h"
#include "edhoc_cipher_suite_0.h"
#include "edhoc_common_internal.h"
#include "edhoc_context_internal.h"
#include <edhoc/coap.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */

extern const struct edhoc_crypto *internals_crypto;

/*
 * Publish a known PRK (raw bytes) as a key-store handle in the given slot so the
 * white-box tests can drive the internal KDF helpers without a full handshake.
 */
extern void internals_inject_prk(struct edhoc_context *ctx,
				 enum edhoc_key_slot_id slot,
				 const uint8_t *prk, size_t prk_len);

/*
 * Import a raw scalar as an X25519 ECDH private-key handle (suite 0) and store
 * the handle in \p key_id, for auth_cred.private_key_id in the static-DH tests.
 */
extern void internals_inject_ecdh_key(uint8_t *key_id, const uint8_t *priv,
				      size_t priv_len);

/* Extern variables and constant declarations ------------------------------ */

extern int comp_cid_len(const struct edhoc_connection_id *cid, size_t *len);
extern int comp_id_cred_len(const struct edhoc_auth_credentials *cred,
			    size_t *len);
extern int comp_th_len(size_t th_len, size_t *len);
extern int comp_cred_len(const struct edhoc_auth_credentials *cred,
			 size_t *len);
extern int comp_ead_len(const struct edhoc_context *ctx, size_t *len);
extern int kid_compact_encoding(const struct edhoc_auth_credentials *cred,
				struct mac_context *mac_ctx);
extern int compute_prk_out(struct edhoc_context *ctx);
extern int compute_new_prk_out(struct edhoc_context *ctx,
			       const uint8_t *entropy, size_t entropy_len);
extern int compute_prk_exporter(struct edhoc_context *ctx);
extern int comp_th_2(struct edhoc_context *ctx);
extern int comp_prk_2e(struct edhoc_context *ctx);
extern int comp_prk_3e2m(struct edhoc_context *ctx,
			 const struct edhoc_auth_credentials *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len);
extern int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len);
extern int comp_encapsulate(struct edhoc_context *ctx);
extern int comp_decapsulate(struct edhoc_context *ctx);
extern int comp_keystream(const struct edhoc_context *ctx, uint8_t *keystream,
			  size_t keystream_len);
extern int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);
extern int comp_grx(struct edhoc_context *ctx,
		    const struct edhoc_auth_credentials *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len);
extern int comp_plaintext_2_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_2_len);
extern int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);
extern int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ciphertext, size_t ciphertext_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len);
extern int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len);
extern int parse_plaintext_2(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len, struct plaintext *parsed_ptxt);
extern int comp_prk_4e3m(struct edhoc_context *ctx,
			 const struct edhoc_auth_credentials *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len);
extern int comp_salt_4e3m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len);
extern int comp_key_iv_aad_3(const struct edhoc_context *ctx, uint8_t *key,
			     size_t key_len, uint8_t *iv, size_t iv_len,
			     uint8_t *aad, size_t aad_len);
extern int comp_th_4(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);
extern int comp_giy(struct edhoc_context *ctx,
		    const struct edhoc_auth_credentials *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len);
extern int comp_plaintext_3_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_3_len);
extern int prepare_plaintext_3(const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);
extern int comp_aad_3_len(const struct edhoc_context *ctx, size_t *aad_3_len);
extern int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
		     size_t msg_3_size, size_t *msg_3_len);
extern int parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len);
extern int decrypt_ciphertext_3(const struct edhoc_context *ctx,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *aad, size_t aad_len,
				const uint8_t *ctxt, size_t ctxt_len,
				uint8_t *ptxt, size_t ptxt_len);
extern int parse_plaintext_3(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len, struct plaintext *parsed_ptxt);
extern int compute_plaintext_4_len(const struct edhoc_context *ctx,
				   size_t *ptxt_4_len);
extern int compute_key_iv_aad_4(const struct edhoc_context *ctx, uint8_t *key,
				size_t key_len, uint8_t *iv, size_t iv_len,
				uint8_t *aad, size_t aad_len);
extern int prepare_plaintext_4(const struct edhoc_context *ctx, uint8_t *ptxt,
			       size_t ptxt_size, size_t *ptxt_len);
extern int gen_msg_4(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_4,
		     size_t msg_4_size, size_t *msg_4_len);
extern int parse_msg_4(const uint8_t *msg_4, size_t msg_4_len,
		       const uint8_t **ctxt_4, size_t *ctxt_4_len);
extern int parse_plaintext_4(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len);

/* Module interface function declarations ---------------------------------- */

void internals_setup_crypto_context(struct edhoc_context *ctx);

#endif /* INTERNALS_COMMON_H */
