/**
 * \file    edhoc_test_hooks.h
 * \author  Kamil Kielbasa
 * \brief   Test-only wrappers for internal static functions.
 *
 *          When LIBEDHOC_TEST_HOOKS is defined at library compile time, each
 *          static function gets a non-static edhoc_test_* wrapper that the test
 *          binary can call directly.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 */

#ifndef EDHOC_TEST_HOOKS_H
#define EDHOC_TEST_HOOKS_H

#ifdef LIBEDHOC_TEST_HOOKS

#include "edhoc_context.h"
#include "edhoc_credentials.h"
#include "edhoc_common.h"

/** \defgroup edhoc-test-hooks EDHOC test hooks
 *
 * Non-static wrappers for internal static functions, available only when
 * LIBEDHOC_TEST_HOOKS is defined at library compile time.  Each wrapper
 * delegates directly to the corresponding static function so that unit
 * tests can exercise internal code paths.
 *
 * @{
 */

/* ---- edhoc_common.c ---- */

/** \brief Compute CBOR-encoded length of a connection identifier. */
int edhoc_test_comp_cid_len(const struct edhoc_connection_id *cid, size_t *len);
/** \brief Compute CBOR-encoded length of ID_CRED (credential identifier). */
int edhoc_test_comp_id_cred_len(const struct edhoc_auth_creds *cred,
				size_t *len);
/** \brief Compute CBOR-encoded length of a transcript hash value. */
int edhoc_test_comp_th_len(size_t th_len, size_t *len);
/** \brief Compute CBOR-encoded length of CRED (authentication credentials). */
int edhoc_test_comp_cred_len(const struct edhoc_auth_creds *cred, size_t *len);
/** \brief Compute CBOR-encoded length of EAD tokens in the context. */
int edhoc_test_comp_ead_len(const struct edhoc_context *ctx, size_t *len);
/** \brief Perform kid compact encoding into the MAC context. */
int edhoc_test_kid_compact_encoding(const struct edhoc_auth_creds *cred,
				    struct mac_context *mac_ctx);

/* ---- edhoc_exporter.c ---- */

/** \brief Compute PRK_out from the EDHOC context. */
int edhoc_test_compute_prk_out(struct edhoc_context *ctx);
/** \brief Compute new PRK_out using additional entropy (key update). */
int edhoc_test_compute_new_prk_out(struct edhoc_context *ctx,
				   const uint8_t *entropy, size_t entropy_len);
/** \brief Compute PRK_exporter from the EDHOC context. */
int edhoc_test_compute_prk_exporter(const struct edhoc_context *ctx,
				    uint8_t *prk_exp, size_t prk_exp_len);

/* ---- edhoc_message_2.c ---- */

/** \brief Compute transcript hash TH_2. */
int edhoc_test_comp_th_2(struct edhoc_context *ctx);
/** \brief Compute pseudorandom key PRK_2e. */
int edhoc_test_comp_prk_2e(struct edhoc_context *ctx);
/** \brief Compute pseudorandom key PRK_3e2m. */
int edhoc_test_comp_prk_3e2m(struct edhoc_context *ctx,
			     const struct edhoc_auth_creds *auth_cred,
			     const uint8_t *pub_key, size_t pub_key_len);
/** \brief Compute SALT_3e2m from the EDHOC context. */
int edhoc_test_comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			      size_t salt_len);
/** \brief Generate ephemeral Diffie-Hellman key pair. */
int edhoc_test_gen_dh_keys(struct edhoc_context *ctx);
/** \brief Compute Diffie-Hellman shared secret. */
int edhoc_test_comp_dh_secret(struct edhoc_context *ctx);
/** \brief Compute KEYSTREAM_2 for XOR encryption. */
int edhoc_test_comp_keystream(const struct edhoc_context *ctx,
			      const uint8_t *prk_2e, size_t prk_2e_len,
			      uint8_t *keystream, size_t keystream_len);
/** \brief Compute transcript hash TH_3. */
int edhoc_test_comp_th_3(struct edhoc_context *ctx,
			 const struct mac_context *mac_ctx, const uint8_t *ptxt,
			 size_t ptxt_len);
/** \brief Compute G_RX (static DH shared secret for responder). */
int edhoc_test_comp_grx(struct edhoc_context *ctx,
			const struct edhoc_auth_creds *auth_cred,
			const uint8_t *pub_key, size_t pub_key_len,
			uint8_t *grx, size_t grx_len);
/** \brief Compute required length for PLAINTEXT_2. */
int edhoc_test_comp_plaintext_2_len(const struct edhoc_context *ctx,
				    const struct mac_context *mac_ctx,
				    size_t sign_len, size_t *plaintext_2_len);
/** \brief CBOR-encode PLAINTEXT_2. */
int edhoc_test_prepare_plaintext_2(const struct edhoc_context *ctx,
				   const struct mac_context *mac_ctx,
				   const uint8_t *sign, size_t sign_len,
				   uint8_t *ptxt, size_t ptxt_size,
				   size_t *ptxt_len);
/** \brief CBOR-encode message 2 from ciphertext. */
int edhoc_test_prepare_message_2(const struct edhoc_context *ctx,
				 const uint8_t *ciphertext,
				 size_t ciphertext_len, uint8_t *msg_2,
				 size_t msg_2_size, size_t *msg_2_len);
/** \brief Parse raw message 2 and extract ciphertext. */
int edhoc_test_parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
			   size_t msg_2_len, uint8_t *ctxt_2,
			   size_t ctxt_2_len);
/** \brief Parse PLAINTEXT_2 into structured fields. */
int edhoc_test_parse_plaintext_2(struct edhoc_context *ctx, const uint8_t *ptxt,
				 size_t ptxt_len,
				 struct plaintext *parsed_ptxt);

/* ---- edhoc_message_3.c ---- */

/** \brief Compute pseudorandom key PRK_4e3m. */
int edhoc_test_comp_prk_4e3m(struct edhoc_context *ctx,
			     const struct edhoc_auth_creds *auth_cred,
			     const uint8_t *pub_key, size_t pub_key_len);
/** \brief Compute SALT_4e3m from the EDHOC context. */
int edhoc_test_comp_salt_4e3m(const struct edhoc_context *ctx, uint8_t *salt,
			      size_t salt_len);
/** \brief Compute K_3, IV_3 and AAD_3 for message 3 encryption. */
int edhoc_test_comp_key_iv_aad_3(const struct edhoc_context *ctx, uint8_t *key,
				 size_t key_len, uint8_t *iv, size_t iv_len,
				 uint8_t *aad, size_t aad_len);
/** \brief Compute transcript hash TH_4. */
int edhoc_test_comp_th_4(struct edhoc_context *ctx,
			 const struct mac_context *mac_ctx, const uint8_t *ptxt,
			 size_t ptxt_len);
/** \brief Compute G_IY (static DH shared secret for initiator). */
int edhoc_test_comp_giy(struct edhoc_context *ctx,
			const struct edhoc_auth_creds *auth_cred,
			const uint8_t *pub_key, size_t pub_key_len,
			uint8_t *giy, size_t giy_len);
/** \brief Compute required length for PLAINTEXT_3. */
int edhoc_test_comp_plaintext_3_len(const struct edhoc_context *ctx,
				    const struct mac_context *mac_ctx,
				    size_t sign_len, size_t *plaintext_3_len);
/** \brief CBOR-encode PLAINTEXT_3. */
int edhoc_test_prepare_plaintext_3(const struct mac_context *mac_ctx,
				   const uint8_t *sign, size_t sign_len,
				   uint8_t *ptxt, size_t ptxt_size,
				   size_t *ptxt_len);
/** \brief Compute required AAD_3 length. */
int edhoc_test_comp_aad_3_len(const struct edhoc_context *ctx,
			      size_t *aad_3_len);
/** \brief CBOR-encode message 3 from ciphertext. */
int edhoc_test_gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
			 size_t msg_3_size, size_t *msg_3_len);
/** \brief Parse raw message 3 and extract ciphertext pointer. */
int edhoc_test_parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
			   const uint8_t **ctxt_3, size_t *ctxt_3_len);
/** \brief Decrypt CIPHERTEXT_3 into PLAINTEXT_3. */
int edhoc_test_decrypt_ciphertext_3(const struct edhoc_context *ctx,
				    const uint8_t *key, size_t key_len,
				    const uint8_t *iv, size_t iv_len,
				    const uint8_t *aad, size_t aad_len,
				    const uint8_t *ctxt, size_t ctxt_len,
				    uint8_t *ptxt, size_t ptxt_len);
/** \brief Parse PLAINTEXT_3 into structured fields. */
int edhoc_test_parse_plaintext_3(struct edhoc_context *ctx, const uint8_t *ptxt,
				 size_t ptxt_len,
				 struct plaintext *parsed_ptxt);

/* ---- edhoc_message_4.c ---- */

/** \brief Compute required length for PLAINTEXT_4. */
int edhoc_test_compute_plaintext_4_len(const struct edhoc_context *ctx,
				       size_t *ptxt_4_len);
/** \brief Compute K_4, IV_4 and AAD_4 for message 4 encryption. */
int edhoc_test_compute_key_iv_aad_4(const struct edhoc_context *ctx,
				    uint8_t *key, size_t key_len, uint8_t *iv,
				    size_t iv_len, uint8_t *aad,
				    size_t aad_len);
/** \brief CBOR-encode PLAINTEXT_4. */
int edhoc_test_prepare_plaintext_4(const struct edhoc_context *ctx,
				   uint8_t *ptxt, size_t ptxt_size,
				   size_t *ptxt_len);
/** \brief CBOR-encode message 4 from ciphertext. */
int edhoc_test_gen_msg_4(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_4,
			 size_t msg_4_size, size_t *msg_4_len);
/** \brief Parse raw message 4 and extract ciphertext pointer. */
int edhoc_test_parse_msg_4(const uint8_t *msg_4, size_t msg_4_len,
			   const uint8_t **ctxt_4, size_t *ctxt_4_len);
/** \brief Parse PLAINTEXT_4 and update EDHOC context. */
int edhoc_test_parse_plaintext_4(struct edhoc_context *ctx, const uint8_t *ptxt,
				 size_t ptxt_len);

/**@}*/

#endif /* LIBEDHOC_TEST_HOOKS */
#endif /* EDHOC_TEST_HOOKS_H */
