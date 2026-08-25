/**
 * \file    edhoc_plaintext_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC plaintext of messages 2, 3 and 4 (RFC 9528: 5.3.2, 5.4.2,
 *          5.5.2).
 *
 *          The three differ in content, not in purpose, so the caller names
 *          which one it means and the module keeps the differences inside.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_PLAINTEXT_INTERNAL_H
#define EDHOC_PLAINTEXT_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* EDHOC public headers: */
#include <edhoc/types.h>
#include <edhoc/credentials.h>

/* EDHOC internal headers: */
#include "edhoc_credentials_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-plaintext-types EDHOC plaintext types
 * @{
 */

/** EDHOC context, defined by \c edhoc_context_internal.h. */
struct edhoc_context;

/** MAC context, defined by \c edhoc_mac_internal.h. */
struct mac_context;

/**
 * \brief Which plaintext the caller means.
 *
 *        The prefix names the protocol flow, so a future flow adds its own
 *        identifiers here rather than overloading these.
 */
enum edhoc_plaintext_id {
	/** PLAINTEXT_2 of classic EDHOC: C_R, ID_CRED_R, Signature_or_MAC_2
	 *  and optional EAD_2. */
	EDHOC_PLAINTEXT_CLASSIC_2,
	/** PLAINTEXT_3 of classic EDHOC: ID_CRED_I, Signature_or_MAC_3 and
	 *  optional EAD_3. */
	EDHOC_PLAINTEXT_CLASSIC_3,
	/** PLAINTEXT_4 of classic EDHOC: optional EAD_4 and nothing else. */
	EDHOC_PLAINTEXT_CLASSIC_4,
	/** PLAINTEXT_2A of EDHOC-PSK: C_R and optional EAD_2. */
	EDHOC_PLAINTEXT_PSK_2A,
	/** PLAINTEXT_3A of EDHOC-PSK: ID_CRED_PSK and CIPHERTEXT_3B. */
	EDHOC_PLAINTEXT_PSK_3A,
	/** PLAINTEXT_3B of EDHOC-PSK: optional EAD_3 and nothing else. */
	EDHOC_PLAINTEXT_PSK_3B,
};

/**
 * \brief Items carried by a plaintext, as decoded.
 *
 *        \ref EDHOC_PLAINTEXT_CLASSIC_4 and \ref EDHOC_PLAINTEXT_PSK_3B carry
 *        none of these, and \ref EDHOC_PLAINTEXT_PSK_2A carries only \p ead.
 */
struct plaintext {
	/** ID_CRED_x, as received from the peer. */
	struct edhoc_credential_received peer_credential_id;

	/** Backing store for a 'kid' that arrived in the CBOR integer form
	 *  (RFC 9528: 3.3.2). */
	uint8_t kid_byte;

	/** Cborised Signature_or_MAC (2/3). */
	struct edhoc_buffer sign_or_mac;

	/** Cborised EAD (2/3). */
	struct edhoc_buffer ead;

	/** CIPHERTEXT_3B, for \ref EDHOC_PLAINTEXT_PSK_3A. */
	struct edhoc_buffer ciphertext_3b;
};

/**
 * \brief What a plaintext is assembled from.
 *
 *        \ref EDHOC_PLAINTEXT_CLASSIC_4, \ref EDHOC_PLAINTEXT_PSK_2A and
 *        \ref EDHOC_PLAINTEXT_PSK_3B need neither the MAC context nor a
 *        signature, and leave both unset.
 */
struct edhoc_plaintext_input {
	/** Which plaintext to build or measure. */
	enum edhoc_plaintext_id id;

	/** MAC context holding the already encoded ID_CRED and EAD. */
	const struct mac_context *mac_context;

	/** Signature_or_MAC. */
	const uint8_t *signature;
	/** Size of \p signature in bytes. */
	size_t signature_length;

	/** ID_CRED_PSK in the compact encoding, for
	 *  \ref EDHOC_PLAINTEXT_PSK_3A. */
	const uint8_t *id_cred_psk;
	/** Size of \p id_cred_psk in bytes. */
	size_t id_cred_psk_length;

	/** CIPHERTEXT_3B, for \ref EDHOC_PLAINTEXT_PSK_3A. */
	const uint8_t *ciphertext_3b;
	/** Size of \p ciphertext_3b in bytes. */
	size_t ciphertext_3b_length;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-plaintext EDHOC plaintext
 * @{
 */

/**
 * \brief Number of bytes the plaintext occupies once encoded.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[in] input                     Plaintext to measure.
 * \param[out] length                   On success, the encoded size.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_plaintext_length(const struct edhoc_context *ctx,
			   const struct edhoc_plaintext_input *input,
			   size_t *length);

/**
 * \brief Assemble the plaintext.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[in] input                     Plaintext to assemble.
 * \param[out] plaintext                Buffer for the plaintext.
 * \param plaintext_size                Size of the \p plaintext buffer in bytes.
 * \param[out] plaintext_length         On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_plaintext_compose(const struct edhoc_context *ctx,
			    const struct edhoc_plaintext_input *input,
			    uint8_t *plaintext, size_t plaintext_size,
			    size_t *plaintext_length);

/**
 * \brief Decode the plaintext.
 *
 *        The decoded items point into \p plaintext, so \p parsed stays valid
 *        only as long as that buffer does. \ref EDHOC_PLAINTEXT_CLASSIC_4
 *        carries no such items and ignores \p parsed, which may be \c NULL;
 *        its EAD goes straight into the context.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param id                            Which plaintext to decode.
 * \param[in] plaintext                 Plaintext to decode.
 * \param plaintext_length              Size of the \p plaintext buffer in bytes.
 * \param[out] parsed                   On success, the decoded items.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_plaintext_parse(struct edhoc_context *ctx, enum edhoc_plaintext_id id,
			  const uint8_t *plaintext, size_t plaintext_length,
			  struct plaintext *parsed);

/**@}*/

#endif /* EDHOC_PLAINTEXT_INTERNAL_H */
