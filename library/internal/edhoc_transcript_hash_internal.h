/**
 * \file    edhoc_transcript_hash_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC transcript hash (RFC 9528: 5.2.2, 5.3.2, 5.4.2, 5.5.2).
 *
 *          TH_1 to TH_4 are one chain: every value hashes the previous one
 *          together with the material the message just contributed, and all of
 *          them live in the same context field. One entry point computes them
 *          so the chaining rule exists once.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_TRANSCRIPT_HASH_INTERNAL_H
#define EDHOC_TRANSCRIPT_HASH_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* EDHOC internal headers: */
#include "edhoc_context_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-transcript-hash-types EDHOC transcript hash types
 * @{
 */

/**
 * \brief Material a transcript hash needs on top of the context.
 *
 *        Each target reads only its own fields, and which fields those are
 *        depends on the authentication family.
 *
 *        Classic EDHOC (RFC 9528: 5.3.2, 5.4.2), methods 0 to 3:
 *        - TH_1 = H( message_1 ): \p message_1.
 *        - TH_2: nothing; both ephemeral values are already in the context.
 *        - TH_3 = H( TH_2, PLAINTEXT_2, CRED_R ): \p plaintext and
 *          \p credential.
 *        - TH_4 = H( TH_3, PLAINTEXT_3, CRED_I ): \p plaintext and
 *          \p credential.
 *
 *        EDHOC-PSK (draft-ietf-lake-edhoc-psk: 4), method 4:
 *        - TH_1 and TH_2 as above.
 *        - TH_3 = H( TH_2, PLAINTEXT_2A ): \p plaintext only, because
 *          message 2 carries no credential.
 *        - TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_I, CRED_R ):
 *          \p plaintext, \p credential, \p id_cred and \p peer_credential.
 *          PLAINTEXT_3B is empty when message 3 carries no EAD_3.
 */
struct edhoc_th_input {
	/** Transcript hash to compute; the previous one must be current. */
	enum edhoc_th_state target;

	/** TH_1: CBOR-encoded message_1. */
	const uint8_t *message_1;
	/** Size of the \p message_1 buffer in bytes. */
	size_t message_1_length;

	/** TH_3: PLAINTEXT_2, or PLAINTEXT_2A under method 4.
	 *  TH_4: PLAINTEXT_3, or PLAINTEXT_3B under method 4. */
	const uint8_t *plaintext;
	/** Size of the \p plaintext buffer in bytes. */
	size_t plaintext_length;

	/** TH_3: CRED_R, unused under method 4. TH_4: CRED_I. Already
	 *  CBOR-encoded. */
	const uint8_t *credential;
	/** Size of the \p credential buffer in bytes. */
	size_t credential_length;

	/** TH_4 under method 4: ID_CRED_PSK. Already CBOR-encoded. */
	const uint8_t *id_cred;
	/** Size of the \p id_cred buffer in bytes. */
	size_t id_cred_length;

	/** TH_4 under method 4: CRED_R. Already CBOR-encoded. */
	const uint8_t *peer_credential;
	/** Size of the \p peer_credential buffer in bytes. */
	size_t peer_credential_length;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-transcript-hash EDHOC transcript hash
 * @{
 */

/**
 * \brief Compute the next transcript hash into the context.
 *
 *        Requires the preceding transcript hash to be the current one, and on
 *        success replaces it with \p input->target. The context field is both
 *        an input and the output: the multipart hash consumes the previous
 *        value before the digest overwrites it.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param[in] input                     Material for the requested hash.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_th_compute(struct edhoc_context *ctx,
		     const struct edhoc_th_input *input);

/**
 * \brief Number of bytes a transcript hash occupies once CBOR-encoded as a
 *        byte string.
 *
 * \param th_length                     Transcript hash length in bytes.
 * \param[out] length                   On success, the encoded size.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_th_encoded_length(size_t th_length, size_t *length);

/**@}*/

#endif /* EDHOC_TRANSCRIPT_HASH_INTERNAL_H */
