/**
 * \file    edhoc_context_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC context definition (library-internal).
 *
 *          \ref edhoc_context is opaque to consumers: \c <edhoc/edhoc.h> only
 *          forward-declares it and exposes \ref edhoc_context_size. The full
 *          layout lives here, visible to the library core and to white-box
 *          tests that add \c library/internal to their private include path.
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
#include <edhoc/types.h>
#include <edhoc/platform.h>
#include <edhoc/credentials.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/crypto.h>
#include <edhoc/ead.h>
#include <edhoc/values.h>

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
	/** Initiator. */
	EDHOC_ROLE_INITIATOR,
	/** Responder. */
	EDHOC_ROLE_RESPONDER,
};

/**
 * \brief RFC 9528: Appendix I. Example Protocol State Machine.
 */
enum edhoc_state_machine {
	/** Start. */
	EDHOC_SM_START,
	/** Aborted. */
	EDHOC_SM_ABORTED,

	/* Responder: */

	/** Received message 1. */
	EDHOC_SM_RECEIVED_M1,
	/** Verified message 1. */
	EDHOC_SM_VERIFIED_M1,

	/* Initiator: */

	/** Waiting for message 2. */
	EDHOC_SM_WAIT_M2,
	/** Received message 2. */
	EDHOC_SM_RECEIVED_M2,
	/** Verified message 2. */
	EDHOC_SM_VERIFIED_M2,

	/* Responder: */

	/** Waiting for message 3. */
	EDHOC_SM_WAIT_M3,
	/** Received message 3. */
	EDHOC_SM_RECEIVED_M3,

	/* Initiator: */

	/** Received message 4. */
	EDHOC_SM_RECEIVED_M4,

	/** Completed. */
	EDHOC_SM_COMPLETED,
	/** Persisted. */
	EDHOC_SM_PERSISTED,
};

/**
 * \brief EDHOC transcript hashes states.
 */
enum edhoc_th_state {
	/** Invalid. */
	EDHOC_TH_STATE_INVALID,
	/** TH_1. */
	EDHOC_TH_STATE_1,
	/** TH_2. */
	EDHOC_TH_STATE_2,
	/** TH_3. */
	EDHOC_TH_STATE_3,
	/** TH_4. */
	EDHOC_TH_STATE_4,
};

/**
 * \brief EDHOC pseudorandom keys states.
 */
enum edhoc_prk_state {
	/** Invalid. */
	EDHOC_PRK_STATE_INVALID,
	/** PRK_2e (RFC 9528: 4.1.1.1). */
	EDHOC_PRK_STATE_2E,
	/** PRK_3e2m (RFC 9528: 4.1.1.2). */
	EDHOC_PRK_STATE_3E2M,
	/** PRK_4e3m (RFC 9528: 4.1.1.3). */
	EDHOC_PRK_STATE_4E3M,
	/** PRK_out (RFC 9528: 4.1.3). */
	EDHOC_PRK_STATE_OUT,
	/** PRK_exporter (RFC 9528: 4.2.1). */
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
	/** PRK_2e (RFC 9528: 4.1.1.1). */
	EDHOC_KEY_SLOT_PRK_2E,
	/** PRK_3e2m (RFC 9528: 4.1.1.2). */
	EDHOC_KEY_SLOT_PRK_3E2M,
	/** Own ephemeral private (KEM decapsulation) key; kept until message 3
	 *  for the static-DH methods (2/3). */
	EDHOC_KEY_SLOT_EPHEMERAL,
	/** Static-DH shared secret \c G_IY (IKM for PRK_4e3m, message 3). */
	EDHOC_KEY_SLOT_G_IY,
	/** Message 3 content-encryption key \c K_3 (AEAD, derived from PRK_3e2m). */
	EDHOC_KEY_SLOT_K_3,
	/** Message 4 content-encryption key \c K_4 (AEAD, derived from PRK_4e3m). */
	EDHOC_KEY_SLOT_K_4,
	/** PRK_4e3m (RFC 9528: 4.1.1.3). */
	EDHOC_KEY_SLOT_PRK_4E3M,
	/** PRK_out (RFC 9528: 4.1.3). */
	EDHOC_KEY_SLOT_PRK_OUT,
	/** PRK_exporter (RFC 9528: 4.2.1). */
	EDHOC_KEY_SLOT_PRK_EXPORTER,
	/** Number of key slots (sentinel, not a slot). */
	EDHOC_KEY_SLOT_COUNT,
};

/**
 * \brief A key-store handle slot.
 */
struct edhoc_key_slot {
	/** Backend key-store handle. */
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN];
	/** Set while \p key_id holds a live key-store handle. */
	bool present;
};

/**
 * \brief The bound EDHOC interfaces together with their "present" flags.
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
 * \brief A list of authentication methods.
 */
struct edhoc_method_list {
	/** Method entries. */
	enum edhoc_method entry[CONFIG_LIBEDHOC_MAX_NR_OF_METHODS];
	/** Number of live entries in \p entry. */
	size_t count;
};

/**
 * \brief A list of cipher suites.
 */
struct edhoc_cipher_suite_list {
	/** Cipher suite entries. */
	struct edhoc_cipher_suite entry[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Number of live entries in \p entry. */
	size_t count;
};

/**
 * \brief Negotiated session parameters: method, cipher suite and connection
 *        identifier (local + peer), each paired with the "present" flag its
 *        \c edhoc_set_* setter raises.
 */
struct edhoc_negotiation {
	/** Selected authentication method. */
	enum edhoc_method selected_method;
	/** Locally supported methods. */
	struct edhoc_method_list method;

	/** Index of the selected suite in \p cipher_suite. */
	size_t selected_cipher_suite_index;
	/** Locally supported cipher suites. */
	struct edhoc_cipher_suite_list cipher_suite;
	/** Peer's advertised cipher suites. */
	struct edhoc_cipher_suite_list peer_cipher_suite;

	/** Own connection identifier. */
	struct edhoc_connection_id connection_id;
	/** Peer connection identifier. */
	struct edhoc_connection_id peer_connection_id;

	/** Set once \ref edhoc_set_methods succeeds. */
	bool methods_present : 1;
	/** Set once \ref edhoc_set_cipher_suites succeeds. */
	bool cipher_suites_present : 1;
	/** Set once \ref edhoc_set_connection_id succeeds. */
	bool connection_id_present : 1;
};

/**
 * \brief EDHOC transcript hash: the running value paired with the schedule
 *        stage it currently represents (parallels \ref edhoc_key_slot).
 */
struct edhoc_transcript_hash {
	/** Which transcript hash the buffer currently holds. */
	enum edhoc_th_state stage;
	/** Transcript-hash bytes. */
	uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_MAC];
	/** Size of \p value in bytes. */
	size_t length;
};

/**
 * \brief Runtime protocol state: where the handshake currently is.
 */
struct edhoc_protocol_state {
	/** State machine position (RFC 9528 Appendix I). */
	enum edhoc_state_machine machine;
	/** Message currently being processed. */
	enum edhoc_message message;
	/** Local role (fixed for the session). */
	enum edhoc_role role;
	/** Transcript hash (value + stage). */
	struct edhoc_transcript_hash th;
	/** Pseudorandom-key schedule stage. */
	enum edhoc_prk_state prk_state;
};

/**
 * \brief A public ephemeral value (G_X or G_Y).
 */
struct edhoc_ephemeral_public {
	/** Ephemeral public value bytes. */
	uint8_t value[EDHOC_MAX_LEN_OF_EPHEMERAL_KEY];
	/** Size of \p value in bytes. */
	size_t length;
};

/**
 * \brief The two public ephemeral values exchanged in messages 1 and 2.
 */
struct edhoc_ephemeral_keys {
	/** Own public ephemeral value. */
	struct edhoc_ephemeral_public own;
	/** Peer public ephemeral value. */
	struct edhoc_ephemeral_public peer;
};

/**
 * \brief External authorization data tokens carried across a message.
 */
struct edhoc_ead_tokens {
	/** Token storage. The \c +1 keeps the array non-empty when the Kconfig
	 *  count is 0 (a valid "no EAD" build); usable capacity is
	 *  \c ARRAY_SIZE(token)-1. */
	struct edhoc_ead_token token[CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS + 1];
	/** Number of live tokens in \p token. */
	size_t count;
};

/**
 * \brief EDHOC context.
 */
struct edhoc_context {
	/** Negotiated parameters: method / cipher suite / connection id. */
	struct edhoc_negotiation negotiation;
	/** Runtime protocol state (state machine, role, message, TH, PRK). */
	struct edhoc_protocol_state state;
	/** Public ephemeral values (own + peer). */
	struct edhoc_ephemeral_keys ephemeral;

	/** Key-store handle slots, indexed by \ref edhoc_key_slot_id. */
	struct edhoc_key_slot key_slots[EDHOC_KEY_SLOT_COUNT];

	/** Bound EDHOC interfaces and their "present" flags. */
	struct edhoc_interfaces interfaces;

	/** External authorization data tokens. */
	struct edhoc_ead_tokens ead;

	/** Is context initialized? */
	bool is_init : 1;
	/** Is OSCORE security session export allowed? */
	bool is_oscore_export_allowed : 1;

	/** User context passed to backend callbacks. */
	void *user_context;

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
	return ctx->negotiation.methods_present &&
	       ctx->negotiation.cipher_suites_present &&
	       ctx->negotiation.connection_id_present &&
	       ctx->interfaces.crypto_present &&
	       ctx->interfaces.credentials_present &&
	       ctx->interfaces.platform_present;
}

/**
 * \brief The bound cryptographic backend interface.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return Pointer to the crypto vtable.
 */
static inline const struct edhoc_crypto *
edhoc_crypto(const struct edhoc_context *ctx)
{
	return &ctx->interfaces.crypto;
}

/**
 * \brief Wipe a buffer through the bound platform \c zeroize hook.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[out] buffer                   Buffer to wipe.
 * \param length                        Number of bytes to wipe.
 */
static inline void edhoc_zeroize(const struct edhoc_context *ctx, void *buffer,
				 size_t length)
{
	ctx->interfaces.platform.zeroize(buffer, length);
}

/**
 * \brief The cipher suite selected for this session.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return Pointer to the selected \ref edhoc_cipher_suite.
 */
static inline const struct edhoc_cipher_suite *
edhoc_selected_cipher_suite(const struct edhoc_context *ctx)
{
	const struct edhoc_cipher_suite_list *suites =
		&ctx->negotiation.cipher_suite;

	return &suites->entry[ctx->negotiation.selected_cipher_suite_index];
}

/**
 * \brief Is the local role the Initiator?
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return \c true when the local role is \ref EDHOC_ROLE_INITIATOR.
 */
static inline bool edhoc_is_initiator(const struct edhoc_context *ctx)
{
	return EDHOC_ROLE_INITIATOR == ctx->state.role;
}

/**
 * \brief Is the local role the Responder?
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return \c true when the local role is \ref EDHOC_ROLE_RESPONDER.
 */
static inline bool edhoc_is_responder(const struct edhoc_context *ctx)
{
	return EDHOC_ROLE_RESPONDER == ctx->state.role;
}

/**
 * \brief Wipe all external authorization data tokens.
 *
 * \param[in,out] ctx                   EDHOC context.
 */
static inline void edhoc_ead_reset(struct edhoc_context *ctx)
{
	edhoc_zeroize(ctx, &ctx->ead, sizeof(ctx->ead));
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
	case EDHOC_KEY_SLOT_COUNT:
	default:
		return "unknown";
	}
}

/**
 * \brief Return a pointer to a slot's opaque key-store handle.
 *
 *        The pointed-to buffer is what the crypto backend reads (as an input
 *        handle) or writes (as an output handle). The pointer is non-const so
 *        one accessor serves both roles regardless of how the caller holds
 *        \p ctx; treat the bytes as opaque.
 *
 * \param[in] ctx                       EDHOC context.
 * \param slot                          Key slot to access.
 *
 * \return Pointer to the slot's #CONFIG_LIBEDHOC_KEY_ID_LEN-byte handle buffer.
 */
static inline void *edhoc_key_slot_id(const struct edhoc_context *ctx,
				      enum edhoc_key_slot_id slot)
{
	return (void *)ctx->key_slots[slot].key_id;
}

/**
 * \brief Is a key slot currently holding a live key-store handle?
 *
 * \param[in] ctx                       EDHOC context.
 * \param slot                          Key slot to query.
 *
 * \return \c true when the slot holds a handle.
 */
static inline bool edhoc_key_slot_present(const struct edhoc_context *ctx,
					  enum edhoc_key_slot_id slot)
{
	return ctx->key_slots[slot].present;
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
static inline void edhoc_key_slot_move(struct edhoc_context *ctx,
				       enum edhoc_key_slot_id dst_slot,
				       enum edhoc_key_slot_id src_slot)
{
	struct edhoc_key_slot *dst = &ctx->key_slots[dst_slot];
	struct edhoc_key_slot *src = &ctx->key_slots[src_slot];

	memcpy(dst->key_id, src->key_id, sizeof(dst->key_id));
	dst->present = true;

	ctx->interfaces.platform.zeroize(src->key_id, sizeof(src->key_id));
	src->present = false;
}

/**
 * \brief Copy a slot's key-store handle into a caller-provided buffer.
 *
 * \param[in] ctx                       EDHOC context.
 * \param slot                          Source key slot.
 * \param[out] key_id                   Buffer of #CONFIG_LIBEDHOC_KEY_ID_LEN bytes.
 */
static inline void edhoc_key_slot_snapshot(const struct edhoc_context *ctx,
					   enum edhoc_key_slot_id slot,
					   uint8_t *key_id)
{
	memcpy(key_id, ctx->key_slots[slot].key_id,
	       sizeof(ctx->key_slots[slot].key_id));
}

/**
 * \brief Write a key-store handle into a slot and mark the slot present.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param slot                          Destination key slot.
 * \param[in] key_id                    Buffer of #CONFIG_LIBEDHOC_KEY_ID_LEN bytes.
 */
static inline void edhoc_key_slot_restore(struct edhoc_context *ctx,
					  enum edhoc_key_slot_id slot,
					  const uint8_t *key_id)
{
	struct edhoc_key_slot *key_slot = &ctx->key_slots[slot];

	memcpy(key_slot->key_id, key_id, sizeof(key_slot->key_id));
	key_slot->present = true;
}

/**
 * \brief Mark a key slot as holding a live key-store handle.
 *
 *        Call after a crypto operation has written a handle into the slot's
 *        \ref edhoc_key_slot.key_id.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param slot                          Key slot that now holds a handle.
 */
static inline void edhoc_key_slot_mark_present(struct edhoc_context *ctx,
					       enum edhoc_key_slot_id slot)
{
	ctx->key_slots[slot].present = true;
}

/**
 * \brief Destroy the live key-store handle held by a single slot.
 *
 *        Destroys the backend handle when the slot is present, then wipes its
 *        identifier and clears the "present" flag. A slot that is not present,
 *        or a context without a bound \c destroy_key, is a successful no-op.
 *        On a destroy failure the slot is left untouched (still present) so the
 *        caller can retry or surface the error.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param slot                          Key slot to release.
 *
 * \return #EDHOC_SUCCESS, or the destroy_key error.
 */
static inline int edhoc_key_slot_release(struct edhoc_context *ctx,
					 enum edhoc_key_slot_id slot)
{
	struct edhoc_key_slot *key_slot = &ctx->key_slots[slot];

	if (!key_slot->present || NULL == ctx->interfaces.crypto.destroy_key) {
		return EDHOC_SUCCESS;
	}

	const int ret = ctx->interfaces.crypto.destroy_key(ctx->user_context,
							   key_slot->key_id);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	ctx->interfaces.platform.zeroize(key_slot->key_id,
					 sizeof(key_slot->key_id));
	key_slot->present = false;

	return EDHOC_SUCCESS;
}

/**
 * \brief Destroy every live key-store handle in slots [0, \p up_to_slot).
 *
 *        Iterates the context key slots up to (but excluding) \p up_to_slot,
 *        releasing each via \ref edhoc_key_slot_release. Already-released slots
 *        are skipped, so each stage releases only the handles it retires:
 *        message 2 up to \ref EDHOC_KEY_SLOT_PRK_3E2M, message 3 up to
 *        \ref EDHOC_KEY_SLOT_PRK_4E3M and \ref edhoc_context_deinit up to
 *        \ref EDHOC_KEY_SLOT_COUNT. The caller is expected to log a diagnostic
 *        on failure.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param up_to_slot                    First slot NOT released (exclusive bound).
 *
 * \return #EDHOC_SUCCESS, or the first destroy error encountered.
 */
static inline int
edhoc_key_slot_release_up_to(struct edhoc_context *ctx,
			     enum edhoc_key_slot_id up_to_slot)
{
	for (enum edhoc_key_slot_id slot = 0; slot < up_to_slot; ++slot) {
		const int ret = edhoc_key_slot_release(ctx, slot);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}
	}

	return EDHOC_SUCCESS;
}

/**
 * \brief Destroy a key-store handle held in a raw buffer and wipe the buffer.
 *
 *        The raw-buffer companion to \ref edhoc_key_slot_release: it operates
 *        on a handle kept outside \ref edhoc_context.key_slots (a local
 *        snapshot, or a caller-owned exporter output) rather than on a key
 *        slot. Destroying a zeroed / no-key handle is a successful no-op.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param[in,out] key_id                Buffer of #CONFIG_LIBEDHOC_KEY_ID_LEN bytes.
 *
 * \return #EDHOC_SUCCESS, or the destroy_key error.
 */
static inline int edhoc_key_destroy(struct edhoc_context *ctx, void *key_id)
{
	int ret = EDHOC_SUCCESS;

	if (NULL != ctx->interfaces.crypto.destroy_key) {
		ret = ctx->interfaces.crypto.destroy_key(ctx->user_context,
							 key_id);
	}

	ctx->interfaces.platform.zeroize(key_id, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return ret;
}

#endif /* EDHOC_CONTEXT_INTERNAL_H */
