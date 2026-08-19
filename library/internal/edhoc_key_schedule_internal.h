/**
 * \file    edhoc_key_schedule_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC key schedule (RFC 9528: 4.1).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_KEY_SCHEDULE_INTERNAL_H
#define EDHOC_KEY_SCHEDULE_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-key-schedule-types EDHOC key schedule types
 * @{
 */

/** EDHOC context, defined by \c edhoc_context_internal.h. */
struct edhoc_context;

/**
 * \brief How the party that authenticates in a message proves its identity
 *        (RFC 9528: 3.2).
 */
enum edhoc_auth_kind {
	/** Signature over COSE_Sign1. */
	EDHOC_AUTH_SIGNATURE,
	/** Static Diffie-Hellman. */
	EDHOC_AUTH_STATIC_DH,
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-key-schedule EDHOC key schedule
 * @{
 */

/**
 * \brief Authentication kind of the message being handled.
 *
 *        Method numbering pairs the Initiator's and the Responder's
 *        authentication, so the same method means signature in one message and
 *        static Diffie-Hellman in the other. Everything downstream reads that
 *        split from here: the key schedule, the MAC length and the form of
 *        Signature_or_MAC.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[out] kind                     On success, the authentication kind.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_key_schedule_auth_kind(const struct edhoc_context *ctx,
		    enum edhoc_auth_kind *kind);

/**
 * \brief KEM-encapsulate to the peer's G_X (RFC 9528: 5.3.2).
 *
 *        Produces the KEM ciphertext G_Y, stores the shared secret G_XY and
 *        retains the local ephemeral private key for the static-DH agreement
 *        of message 3.
 *
 * \param[in,out] ctx                   EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_key_schedule_encapsulate(struct edhoc_context *ctx);

/**
 * \brief KEM-decapsulate the peer's G_Y with the ephemeral private key from
 *        message 1, yielding the shared secret G_XY.
 *
 * \param[in,out] ctx                   EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_key_schedule_decapsulate(struct edhoc_context *ctx);

/**
 * \brief First link of the chain: derive PRK_2e from the ephemeral shared
 *        secret (RFC 9528: 4.1.1.1).
 *
 *        Unlike the later links this one does not depend on how either party
 *        authenticates, so it needs no key material from the caller.
 *
 * \param[in,out] ctx                   EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_key_schedule_prk_initial(struct edhoc_context *ctx);

/**
 * \brief Advance the pseudorandom key one step: PRK_2e to PRK_3e2m in
 *        message 2, PRK_3e2m to PRK_4e3m in message 3 (RFC 9528: 4.1.1.2,
 *        4.1.1.3).
 *
 *        With signature authentication the key is unchanged and only its
 *        handle moves; with static Diffie-Hellman it is re-extracted from the
 *        static-DH shared secret.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param[in] private_key_id            Handle of the local authentication key,
 *                                      needed when the local party is the one
 *                                      authenticating.
 * \param[in] peer_public_key           Peer authentication public key, needed
 *                                      otherwise.
 * \param peer_public_key_length        Size of \p peer_public_key in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_key_schedule_prk_advance(struct edhoc_context *ctx,
				   const void *private_key_id,
				   const uint8_t *peer_public_key,
				   size_t peer_public_key_length);

/**@}*/

#endif /* EDHOC_KEY_SCHEDULE_INTERNAL_H */
