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
 *        Each target reads only its own fields:
 *        - TH_1: \p message_1.
 *        - TH_2: nothing; both ephemeral values are already in the context.
 *        - TH_3: \p plaintext holds PLAINTEXT_2, \p credential holds CRED_R.
 *        - TH_4: \p plaintext holds PLAINTEXT_3, \p credential holds CRED_I.
 */
struct edhoc_th_input {
	/** Transcript hash to compute; the previous one must be current. */
	enum edhoc_th_state target;

	/** TH_1: CBOR-encoded message_1. */
	const uint8_t *message_1;
	/** Size of the \p message_1 buffer in bytes. */
	size_t message_1_length;

	/** TH_3: PLAINTEXT_2. TH_4: PLAINTEXT_3. */
	const uint8_t *plaintext;
	/** Size of the \p plaintext buffer in bytes. */
	size_t plaintext_length;

	/** TH_3: CRED_R. TH_4: CRED_I. Already CBOR-encoded. */
	const uint8_t *credential;
	/** Size of the \p credential buffer in bytes. */
	size_t credential_length;
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
