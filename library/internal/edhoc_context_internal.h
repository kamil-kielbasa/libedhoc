/**
 * \file    edhoc_context_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC context definition (library-internal).
 *
 *          The \ref edhoc_context structure is opaque to library consumers:
 *          the public header \c <edhoc/edhoc_context.h> only forward-declares
 *          it and exposes \ref edhoc_context_size. The full layout lives here
 *          and is visible to the library core and to white-box tests that add
 *          \c library/internal to their private include path.
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CONTEXT_INTERNAL_H
#define EDHOC_CONTEXT_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* EDHOC public headers (types referenced by the context): */
#include <edhoc/edhoc_types.h>
#include <edhoc/edhoc_platform.h>
#include <edhoc/edhoc_credentials.h>
#include <edhoc/edhoc_cipher_suite.h>
#include <edhoc/edhoc_crypto.h>
#include <edhoc/edhoc_ead.h>
#include <edhoc/edhoc_values.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Defines ----------------------------------------------------------------- */

/**
 * \brief Storage size for an own/peer ephemeral public value.
 *
 *        The Initiator's \c G_X carries the encapsulation key and the
 *        Responder's \c G_Y carries the KEM ciphertext; a single buffer must
 *        hold whichever the local role produces, so it is sized to the larger
 *        of the two (they are equal for the classical NIKE-as-KEM suites).
 */
#define EDHOC_MAX_LEN_OF_EPHEMERAL_KEY                               \
	(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_PUBLIC_KEY >                 \
			 CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT ? \
		 CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_PUBLIC_KEY :         \
		 CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT)

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief RFC 9528: 2. EDHOC Outline.
 */
enum edhoc_role {
	/** EDHOC role - initiator. */
	EDHOC_INITIATOR,
	/** EDHOC role - responder. */
	EDHOC_RESPONDER,
};

/**
 * \brief RFC 9528: Appendix I. Example Protocol State Machine.
 */
enum edhoc_state_machine {
	/** State machine - start. */
	EDHOC_SM_START,
	/** State machine - aborted. */
	EDHOC_SM_ABORTED,

	/* Responder: */

	/** State machine - received message 1. */
	EDHOC_SM_RECEIVED_M1,
	/** State machine - verified message 1. */
	EDHOC_SM_VERIFIED_M1,

	/* Initiator: */

	/** State machine - waiting for message 2. */
	EDHOC_SM_WAIT_M2,
	/** State machine - received message 2. */
	EDHOC_SM_RECEIVED_M2,
	/** State machine - verified message 2. */
	EDHOC_SM_VERIFIED_M2,

	/* Responder: */

	/** State machine - waiting for message 3. */
	EDHOC_SM_WAIT_M3,
	/** State machine - received message 3. */
	EDHOC_SM_RECEIVED_M3,

	/* Initiator: */

	/** State machine - received message 4. */
	EDHOC_SM_RECEIVED_M4,

	/** State machine - completed. */
	EDHOC_SM_COMPLETED,
	/** State machine - persisted. */
	EDHOC_SM_PERSISTED,
};

/**
 * \brief EDHOC transcript hashes states.
 */
enum edhoc_th_state {
	/** Transcript hash invalid. */
	EDHOC_TH_STATE_INVALID,
	/** Transcript hash 1. */
	EDHOC_TH_STATE_1,
	/** Transcript hash 2. */
	EDHOC_TH_STATE_2,
	/** Transcript hash 3. */
	EDHOC_TH_STATE_3,
	/** Transcript hash 4. */
	EDHOC_TH_STATE_4,
};

/**
 * \brief EDHOC pseudorandom keys states.
 */
enum edhoc_prk_state {
	/** Pseudorandom key invalid. */
	EDHOC_PRK_STATE_INVALID,
	/** Pseudorandom key RFC 9528: 4.1.1.1. PRK_2e. */
	EDHOC_PRK_STATE_2E,
	/** Pseudorandom key RFC 9528: 4.1.1.2. PRK_3e2m. */
	EDHOC_PRK_STATE_3E2M,
	/** Pseudorandom key RFC 9528: 4.1.1.3. PRK_4e3m. */
	EDHOC_PRK_STATE_4E3M,
	/** Pseudorandom key RFC 9528: 4.1.3. PRK_out. */
	EDHOC_PRK_STATE_OUT,
	/** Pseudorandom key RFC 9528: 4.2.1. EDHOC_Exporter. */
	EDHOC_PRK_STATE_EXPORTER,
};

/**
 * \brief Identifiers of the key-store handles held by an \ref edhoc_context.
 *
 *        Used to index \ref edhoc_context.key_slots; \ref EDHOC_KEY_SLOT_COUNT
 *        is the number of slots, not a slot itself.
 */
enum edhoc_key_slot_id {
	/** Ephemeral shared secret \c G_XY. */
	EDHOC_KEY_SLOT_SHARED_SECRET,
	/** Static-DH shared secret \c G_RX (IKM for PRK_3e2m, message 2). */
	EDHOC_KEY_SLOT_G_RX,
	/** RFC 9528: 4.1.1.1. PRK_2e. */
	EDHOC_KEY_SLOT_PRK_2E,
	/** RFC 9528: 4.1.1.2. PRK_3e2m. */
	EDHOC_KEY_SLOT_PRK_3E2M,
	/** Local ephemeral (decapsulation) private key: the Initiator's from
	 *  \ref edhoc_crypto.generate_key_pair (message 1) or the Responder's from
	 *  \ref edhoc_crypto.encapsulate (message 2). Retained past message 2 so the
	 *  Responder can compute \c G_IY (message 3 static-DH, methods 2/3). */
	EDHOC_KEY_SLOT_EPHEMERAL,
	/** Static-DH shared secret \c G_IY (IKM for PRK_4e3m, message 3). */
	EDHOC_KEY_SLOT_G_IY,
	/** Message 3 content-encryption key \c K_3 (AEAD, derived from PRK_3e2m). */
	EDHOC_KEY_SLOT_K_3,
	/** Message 4 content-encryption key \c K_4 (AEAD, derived from PRK_4e3m). */
	EDHOC_KEY_SLOT_K_4,
	/** RFC 9528: 4.1.1.3. PRK_4e3m. */
	EDHOC_KEY_SLOT_PRK_4E3M,
	/** RFC 9528: 4.1.3. PRK_out. */
	EDHOC_KEY_SLOT_PRK_OUT,
	/** RFC 9528: 4.2.1. PRK_exporter. */
	EDHOC_KEY_SLOT_PRK_EXPORTER,
	/** Number of key slots (sentinel, not a slot). */
	EDHOC_KEY_SLOT_COUNT,
};

/**
 * \brief A key-store handle slot: the backend key identifier paired with the
 *        liveness flag that says whether the slot currently owns a live key.
 */
struct edhoc_key_slot {
	/** Backend key-store handle. */
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN];
	/** Set while \p key_id holds a live key-store slot. */
	bool present;
};

/**
 * \brief The bound EDHOC interfaces together with their "present" flags.
 *
 *        Grouping each interface with the flag its \c edhoc_bind_* setter
 *        raises keeps all binding state in one place.
 */
struct edhoc_interfaces {
	/** EDHOC interface for cryptographic function operations. */
	struct edhoc_crypto crypto;
	/** EDHOC interface for authentication credentials. */
	struct edhoc_credentials cred;
	/** EDHOC interface for platform services (mandatory \c zeroize). */
	struct edhoc_platform platform;
	/** EDHOC interface for external authorization data. */
	struct edhoc_ead ead;

	/** Set once \ref edhoc_bind_crypto succeeds. */
	bool crypto_present : 1;
	/** Set once \ref edhoc_bind_credentials succeeds. */
	bool credentials_present : 1;
	/** Set once \ref edhoc_bind_platform succeeds. */
	bool platform_present : 1;
	/** Set once \ref edhoc_bind_ead succeeds (optional interface). */
	bool ead_present : 1;
};

/**
 * \brief EDHOC context.
 */
struct edhoc_context {
	/** EDHOC chosen method. */
	enum edhoc_method chosen_method;

	/** EDHOC supported methods. */
	enum edhoc_method method[EDHOC_METHOD_MAX];
	/** Length of the \p method buffer. */
	size_t method_len;

	/** EDHOC cipher suite chosen index. */
	size_t chosen_csuite_idx;
	/** EDHOC cipher suite buffer. */
	struct edhoc_cipher_suite
		csuite[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Length of the \p csuite buffer. */
	size_t csuite_len;
	/** EDHOC peer cipher suite buffer. */
	struct edhoc_cipher_suite
		peer_csuite[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Length of the \p peer_csuite buffer. */
	size_t peer_csuite_len;

	/** EDHOC connection identifier. */
	struct edhoc_connection_id cid;
	/** EDHOC peer connection identifier. */
	struct edhoc_connection_id peer_cid;

	/** Set once \ref edhoc_set_methods succeeds. */
	bool methods_present : 1;
	/** Set once \ref edhoc_set_cipher_suites succeeds. */
	bool cipher_suites_present : 1;
	/** Set once \ref edhoc_set_connection_id succeeds. */
	bool connection_id_present : 1;

	/** EDHOC peer ephemeral public value (peer's \c G_X / \c G_Y). Public. */
	uint8_t peer_pub_eph_key[EDHOC_MAX_LEN_OF_EPHEMERAL_KEY];
	/** Size of the \p peer_pub_eph_key buffer in bytes. */
	size_t peer_pub_eph_key_len;

	/** EDHOC own ephemeral public value (own \c G_X / \c G_Y). Public. */
	uint8_t pub_eph_key[EDHOC_MAX_LEN_OF_EPHEMERAL_KEY];
	/** Size of the \p pub_eph_key buffer in bytes. */
	size_t pub_eph_key_len;

	/** Is context initialized? */
	bool is_init;
	/** Is OSCORE security session export allowed? */
	bool is_oscore_export_allowed;
	/** EDHOC context state machine. */
	enum edhoc_state_machine status;
	/** Current processing EDHOC message. */
	enum edhoc_message message;
	/** EDHOC role. */
	enum edhoc_role role;

	/** EDHOC context transcript hash state. */
	enum edhoc_th_state th_state;
	/** EDHOC context transcript hash buffer. */
	uint8_t th[CONFIG_LIBEDHOC_MAX_LEN_OF_MAC];
	/** Size of the \p th buffer in bytes. */
	size_t th_len;

	/** EDHOC context pseudorandom key state. */
	enum edhoc_prk_state prk_state;

	/** Key-store handle slots, indexed by \ref edhoc_key_slot_id. */
	struct edhoc_key_slot key_slots[EDHOC_KEY_SLOT_COUNT];

	/** Bound EDHOC interfaces and their "present" flags. */
	struct edhoc_interfaces itf;

	/** EDHOC EAD tokens buffer. */
	struct edhoc_ead_token
		ead_token[CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS + 1];
	/** Length of the \p ead_token buffer. */
	size_t nr_of_ead_tokens;

	/** User context. */
	void *user_ctx;

	/** EDHOC error code. */
	enum edhoc_error_code error_code;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/* Static inline function definitions -------------------------------------- */

/**
 * \brief Is every mandatory input present in \p ctx?
 *
 * The mandatory inputs are the local method(s), cipher suite(s) and connection
 * identifier, plus the crypto, credentials and platform interfaces. The
 * external authorization data interface is optional and is not checked here.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return \c true when every mandatory input has been provided.
 */
static inline bool edhoc_context_configured(const struct edhoc_context *ctx)
{
	return ctx->methods_present && ctx->cipher_suites_present &&
	       ctx->connection_id_present && ctx->itf.crypto_present &&
	       ctx->itf.credentials_present && ctx->itf.platform_present;
}

/**
 * \brief Human-readable name of a context key slot, for diagnostics.
 *
 * \param slot                          Key slot identifier.
 *
 * \return Static string naming the slot.
 */
static inline const char *edhoc_key_slot_name(enum edhoc_key_slot_id slot)
{
	switch (slot) {
	case EDHOC_KEY_SLOT_SHARED_SECRET:
		return "shared secret";
	case EDHOC_KEY_SLOT_G_RX:
		return "G_RX";
	case EDHOC_KEY_SLOT_PRK_2E:
		return "PRK_2e";
	case EDHOC_KEY_SLOT_PRK_3E2M:
		return "PRK_3e2m";
	case EDHOC_KEY_SLOT_EPHEMERAL:
		return "ephemeral";
	case EDHOC_KEY_SLOT_G_IY:
		return "G_IY";
	case EDHOC_KEY_SLOT_K_3:
		return "K_3";
	case EDHOC_KEY_SLOT_K_4:
		return "K_4";
	case EDHOC_KEY_SLOT_PRK_4E3M:
		return "PRK_4e3m";
	case EDHOC_KEY_SLOT_PRK_OUT:
		return "PRK_out";
	case EDHOC_KEY_SLOT_PRK_EXPORTER:
		return "PRK_exporter";
	default:
		return "unknown";
	}
}

/**
 * \brief Adopt a live key handle from one slot into another.
 *
 *        Copies the source slot's key identifier into the destination slot and
 *        marks it present, then wipes the source identifier and clears its
 *        present flag. The key-store handle itself is untouched: the same key
 *        simply changes ownership from \p src_slot to \p dst_slot. Used when a
 *        derived key is carried unchanged into the next key-schedule slot
 *        (PRK_2e -> PRK_3e2m for methods 0/2; PRK_3e2m -> PRK_4e3m for methods
 *        0/1) so the shared key is always owned by exactly one slot.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param dst_slot                      Destination slot (receives the handle).
 * \param src_slot                      Source slot (wiped and cleared).
 */
static inline void edhoc_move_key_slot(struct edhoc_context *ctx,
				       enum edhoc_key_slot_id dst_slot,
				       enum edhoc_key_slot_id src_slot)
{
	struct edhoc_key_slot *dst = &ctx->key_slots[dst_slot];
	struct edhoc_key_slot *src = &ctx->key_slots[src_slot];

	memcpy(dst->key_id, src->key_id, sizeof(dst->key_id));
	dst->present = true;

	ctx->itf.platform.zeroize(src->key_id, sizeof(src->key_id));
	src->present = false;
}

/**
 * \brief Destroy every live key-store handle in slots [0, \p up_to_slot).
 *
 *        Iterates the context key slots up to (but excluding) \p up_to_slot,
 *        destroying each backend handle still present, wiping its identifier
 *        and clearing its "present" flag. Already-released slots are skipped,
 *        so each stage releases only the handles it retires: message 2 up to
 *        \ref EDHOC_KEY_SLOT_PRK_3E2M, message 3 up to \ref EDHOC_KEY_SLOT_PRK_4E3M
 *        and \ref edhoc_context_deinit up to \ref EDHOC_KEY_SLOT_COUNT. The
 *        caller is expected to log a diagnostic on failure.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param up_to_slot                    First slot NOT released (exclusive bound).
 *
 * \return #EDHOC_SUCCESS, or the first destroy error encountered.
 */
static inline int edhoc_release_key_slots(struct edhoc_context *ctx,
					  enum edhoc_key_slot_id up_to_slot)
{
	if (NULL == ctx->itf.crypto.destroy_key) {
		return EDHOC_SUCCESS;
	}

	for (enum edhoc_key_slot_id slot = 0; slot < up_to_slot; ++slot) {
		struct edhoc_key_slot *key_slot = &ctx->key_slots[slot];

		if (!key_slot->present) {
			continue;
		}

		const int ret = ctx->itf.crypto.destroy_key(ctx->user_ctx,
							    key_slot->key_id);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}

		ctx->itf.platform.zeroize(key_slot->key_id,
					  sizeof(key_slot->key_id));
		key_slot->present = false;
	}

	return EDHOC_SUCCESS;
}

#endif /* EDHOC_CONTEXT_INTERNAL_H */
