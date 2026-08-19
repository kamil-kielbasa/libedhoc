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

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_transcript_hash_internal.h"
#include "edhoc_mac_internal.h"
#include "edhoc_plaintext_internal.h"
#include "edhoc_key_schedule_internal.h"
#include "edhoc_cipher_internal.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/** \brief Test platform interface (memory wipe) shared by internals tests. */
const struct edhoc_platform *internals_get_platform(void);

/** \brief Init a suite-2 context bound to crypto, credentials and platform. */
void internals_setup_crypto_context(struct edhoc_context *ctx);

/** \brief Publish a raw PRK as a key-store handle in \p slot (white-box KDF). */
void internals_inject_prk(struct edhoc_context *ctx,
			  enum edhoc_key_slot_id slot, const uint8_t *prk,
			  size_t prk_len);

/** \brief Import a raw P-256 scalar as an ECDH private-key handle in \p key_id. */
void internals_inject_ecdh_key(uint8_t *key_id, const uint8_t *priv,
			       size_t priv_len);

/** \brief Generate a valid P-256 ephemeral public key (32-byte X) into \p out. */
void internals_make_ecdh_peer_pub(uint8_t *out, size_t out_size,
				  size_t *out_len);

/* Library-internal functions under test (white-box) ----------------------- */

extern int compute_prk_out(struct edhoc_context *ctx);
extern int compute_new_prk_out(struct edhoc_context *ctx,
			       const uint8_t *entropy, size_t entropy_len);
extern int compute_prk_exporter(struct edhoc_context *ctx);
extern int comp_th_2(struct edhoc_context *ctx);
extern int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);
extern int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ciphertext, size_t ciphertext_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len);
extern int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len);
extern int comp_th_4(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);
extern int prepare_plaintext_3(const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);
extern int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
		     size_t msg_3_size, size_t *msg_3_len);
extern int parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len);
extern int gen_msg_4(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_4,
		     size_t msg_4_size, size_t *msg_4_len);
extern int parse_msg_4(const uint8_t *msg_4, size_t msg_4_len,
		       const uint8_t **ctxt_4, size_t *ctxt_4_len);
extern size_t
cbor_int_or_string_len(const struct edhoc_cbor_int_or_string *value);

#endif /* INTERNALS_COMMON_H */
