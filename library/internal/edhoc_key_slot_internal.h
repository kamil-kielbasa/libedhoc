/**
 * \file    edhoc_key_slot_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC key-store handle slots.
 *
 *          The library never holds raw key material: every secret lives in the
 *          backend key store and the context keeps only opaque handles. This
 *          module owns those slots and the rules for moving, snapshotting and
 *          destroying the handles they carry.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_KEY_SLOT_INTERNAL_H
#define EDHOC_KEY_SLOT_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* Standard library headers: */
#include <stdint.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-key-slot-types EDHOC key slot types
 * @{
 */

/** EDHOC context, defined by \c edhoc_context_internal.h. */
struct edhoc_context;

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
	/** Pre-shared key (IKM for PRK_4e3m, message 3, method 4). Sits before
	 *  PRK_4e3m so the step that spends it also releases it. */
	EDHOC_KEY_SLOT_PSK,
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

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-key-slot EDHOC key slot handling
 * @{
 */

/**
 * \brief Read a slot's opaque key-store handle.
 *
 *        The pointed-to bytes are what the crypto backend consumes as an input
 *        handle; treat them as opaque.
 *
 * \param[in] ctx                       EDHOC context.
 * \param slot                          Key slot to read.
 *
 * \return Pointer to the slot's \c CONFIG_LIBEDHOC_KEY_ID_LEN-byte handle buffer.
 */
const void *edhoc_key_slot_id(const struct edhoc_context *ctx,
			      enum edhoc_key_slot_id slot);

/**
 * \brief Writable view of a slot's opaque key-store handle.
 *
 *        For the operations that produce a handle: the backend writes into the
 *        buffer, after which the slot must be marked live with
 *        \ref edhoc_key_slot_mark_present.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param slot                          Key slot to write.
 *
 * \return Pointer to the slot's \c CONFIG_LIBEDHOC_KEY_ID_LEN-byte handle buffer.
 */
void *edhoc_key_slot_id_mut(struct edhoc_context *ctx,
			    enum edhoc_key_slot_id slot);

/**
 * \brief Is a key slot currently holding a live key-store handle?
 *
 * \param[in] ctx                       EDHOC context.
 * \param slot                          Key slot to query.
 *
 * \return \c true when the slot holds a handle.
 */
bool edhoc_key_slot_present(const struct edhoc_context *ctx,
			    enum edhoc_key_slot_id slot);

/**
 * \brief Mark a key slot as holding a live key-store handle.
 *
 *        Call after a crypto operation has written a handle into the slot's
 *        \ref edhoc_key_slot.key_id.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param slot                          Key slot that now holds a handle.
 */
void edhoc_key_slot_mark_present(struct edhoc_context *ctx,
				 enum edhoc_key_slot_id slot);

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
void edhoc_key_slot_move(struct edhoc_context *ctx,
			 enum edhoc_key_slot_id dst_slot,
			 enum edhoc_key_slot_id src_slot);

/**
 * \brief Copy a slot's key-store handle into a caller-provided buffer.
 *
 * \param[in] ctx                       EDHOC context.
 * \param slot                          Source key slot.
 * \param[out] key_id                   Buffer of \c CONFIG_LIBEDHOC_KEY_ID_LEN bytes.
 */
void edhoc_key_slot_snapshot(const struct edhoc_context *ctx,
			     enum edhoc_key_slot_id slot, uint8_t *key_id);

/**
 * \brief Write a key-store handle into a slot and mark the slot present.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param slot                          Destination key slot.
 * \param[in] key_id                    Buffer of \c CONFIG_LIBEDHOC_KEY_ID_LEN bytes.
 */
void edhoc_key_slot_restore(struct edhoc_context *ctx,
			    enum edhoc_key_slot_id slot, const uint8_t *key_id);

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
int edhoc_key_slot_release(struct edhoc_context *ctx,
			   enum edhoc_key_slot_id slot);

/**
 * \brief Destroy every live key-store handle in slots [0, \p up_to_slot).
 *
 *        Iterates the context key slots up to (but excluding) \p up_to_slot,
 *        releasing each via \ref edhoc_key_slot_release. Already-released slots
 *        are skipped, so each stage releases only the handles it retires:
 *        message 2 up to \ref EDHOC_KEY_SLOT_PRK_3E2M, message 3 up to
 *        \ref EDHOC_KEY_SLOT_PRK_4E3M and \ref edhoc_context_deinit up to
 *        \ref EDHOC_KEY_SLOT_COUNT.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param up_to_slot                    First slot NOT released (exclusive bound).
 *
 * \return #EDHOC_SUCCESS, or the first destroy error encountered.
 */
int edhoc_key_slot_release_up_to(struct edhoc_context *ctx,
				 enum edhoc_key_slot_id up_to_slot);

/**
 * \brief Destroy a key-store handle held in a raw buffer and wipe the buffer.
 *
 *        The raw-buffer companion to \ref edhoc_key_slot_release: it operates
 *        on a handle kept outside \ref edhoc_context.key_slots (a local
 *        snapshot, or a caller-owned exporter output) rather than on a key
 *        slot. Destroying a zeroed / no-key handle is a successful no-op.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param[in,out] key_id                Buffer of \c CONFIG_LIBEDHOC_KEY_ID_LEN bytes.
 *
 * \return #EDHOC_SUCCESS, or the destroy_key error.
 */
int edhoc_key_destroy(struct edhoc_context *ctx, void *key_id);

/**@}*/

#endif /* EDHOC_KEY_SLOT_INTERNAL_H */
