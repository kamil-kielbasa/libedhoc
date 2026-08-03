/**
 * \file    edhoc_common_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC common implementations:
 *          - CBOR utilities.
 *          - MAC context.
 *          - MAC & Signature_or_MAC.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_COMMON_INTERNAL_H
#define EDHOC_COMMON_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* EDHOC headers: */
#include <edhoc/types.h>
#include <edhoc/ead.h>
#include <edhoc/credentials.h>
#include "edhoc_credentials_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */

/** Maximum number of bytes \ref edhoc_cbor_bstr_header can emit: a one-byte
 *  initial byte plus a four-byte length, for payloads up to \c UINT32_MAX. */
#define EDHOC_CBOR_BSTR_HEADER_MAX_LEN (5)

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-common-structures EDHOC common structures
 * @{
 */

/**
 * \brief RFC 9528:
 *        - 5.3.2. Responder Composition of Message 2.
 *          - context_2.
 *        - 5.4.2. Initiator Composition of Message 3.
 *          - context_3.
 */
struct mac_context {
	/** Buffer containing cborised connection identifier. */
	uint8_t *conn_id;
	/** Size of the \p conn_id buffer in bytes. */
	size_t conn_id_len;

	/** Buffer containing cborised credentials identifier. */
	uint8_t *id_cred;
	/** Size of the \p id_cred buffer in bytes. */
	size_t id_cred_len;

	/** Compact ID_CRED (RFC 9528: 3.5.3.2), already CBOR-encoded: a one byte
	 *  integer, or a byte string with its header. Empty when the credential
	 *  is not eligible for the compact encoding. */
	uint8_t id_cred_comp[EDHOC_CREDENTIAL_KID_COMPACT_MAX_LEN];
	/** Number of valid bytes in \p id_cred_comp. */
	size_t id_cred_comp_len;

	/** Buffer containing cborised transcript hash. */
	uint8_t *th;
	/** Size of the \p th buffer in bytes. */
	size_t th_len;

	/** Buffer containing cborised credentials. */
	uint8_t *cred;
	/** Size of the \p cred buffer in bytes. */
	size_t cred_len;

	/** Is EAD attached? */
	bool is_ead;
	/** Buffer containing cborised EAD. */
	uint8_t *ead;
	/** Size of the \p ead buffer in bytes. */
	size_t ead_len;

	/** Size of the \p buf buffer in bytes. */
	size_t buf_len;
	/** Flexible array member buffer. */
	uint8_t buf[];
};

/**
 * \brief RFC 9528:
 *        - 5.3.2. Responder Composition of Message 2.
 *          - PLAINTEXT_2.
 *        - 5.4.2. Initiator Composition of Message 3.
 *          - PLAINTEXT_3.
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
};

/**
 * \brief A single input segment for the multipart transcript-hash helper.
 */
struct hash_segment {
	/** Pointer to the segment bytes. */
	const uint8_t *ptr;
	/** Number of bytes in the segment. */
	size_t len;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-common-cbor EDHOC common CBOR
 * @{
 */

/**
 * \brief Length of the CBOR encoding of an integer.
 *
 * \param value                         Integer value to encode.
 *
 * \return Number of bytes the encoding of \p value occupies.
 */
size_t edhoc_cbor_int_length(int32_t value);

/**
 * \brief Length of the CBOR header framing a text string.
 *
 * \param length                        Length of the text string in bytes.
 *
 * \return Number of header bytes, excluding the string itself.
 */
size_t edhoc_cbor_tstr_header_length(size_t length);

/**
 * \brief Length of the CBOR header framing a byte string.
 *
 * \param length                        Length of the byte string in bytes.
 *
 * \return Number of header bytes, excluding the string itself.
 */
size_t edhoc_cbor_bstr_header_length(size_t length);

/**
 * \brief Check whether a byte is a complete one byte CBOR integer.
 *
 *        RFC 9528: 3.3.2 represents such a byte string by that integer. Applies
 *        to connection identifiers and to a COSE 'kid'.
 *
 * \param value                         Byte to check.
 *
 * \return True if \p value encodes an integer in the range -24..23.
 */
bool edhoc_cbor_is_one_byte_int(uint8_t value);

/**
 * \brief Emit the CBOR byte-string header framing a payload of \p length
 *        bytes, so it can be streamed (e.g. into a hash) without a contiguous
 *        copy of the header and the payload.
 *
 * \param[out] header   Buffer of at least \ref EDHOC_CBOR_BSTR_HEADER_MAX_LEN
 *                      bytes receiving the header.
 * \param length        Length of the byte-string payload.
 *
 * \return Number of header bytes written, zero on invalid arguments.
 */
size_t edhoc_cbor_bstr_header(uint8_t *header, size_t length);

/**
 * \brief Compute CBOR overhead for a map.
 *
 * \param items                         Number of key-value pairs in the map.
 *
 * \return Number of CBOR overhead bytes for encoding a map of \p items pairs.
 */
size_t edhoc_cbor_map_oh(size_t items);

/**
 * \brief Compute CBOR overhead for an array.
 *
 * \param items                         Number of elements in the array.
 *
 * \return Number of CBOR overhead bytes for encoding an array of \p items elements.
 */
size_t edhoc_cbor_array_oh(size_t items);

/**@}*/

/** \defgroup edhoc-common-hash EDHOC common transcript hash
 * @{
 */

/**
 * \brief Compute a hash over an ordered list of byte segments using the
 *        multipart backend interface (init / update.. / finish), avoiding a
 *        contiguous assembly buffer. A single-input caller passes one segment.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[in] segments                  Ordered input segments to hash.
 * \param nr_of_segments                Number of entries in \p segments.
 * \param[out] hash                     Buffer receiving the computed hash.
 * \param hash_size                     Size of the \p hash buffer in bytes.
 * \param[out] hash_len                 On success, number of hash bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_comp_hash(const struct edhoc_context *ctx,
		    const struct hash_segment *segments, size_t nr_of_segments,
		    uint8_t *hash, size_t hash_size, size_t *hash_len);

/**@}*/

/** \defgroup edhoc-common-ead EDHOC common external authorization data
 * @{
 */

/**
 * \brief Validate the EAD items the application produced in
 *        \ref edhoc_ead.compose, then hex-dump the accepted ones at debug
 *        level.
 *
 *        Both the count and the item buffers go straight to the CBOR encoder,
 *        which can neither tell a missing buffer from an empty one nor notice
 *        that a callback reported more items than it was given room for.
 *
 * \param[in] tokens                    EAD items to send.
 * \param nr_of_tokens                  Number of entries in \p tokens.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_validate_ead_composed(const struct edhoc_ead_token *tokens,
				size_t nr_of_tokens);

/**@}*/

/** \defgroup edhoc-common-mac-context EDHOC common MAC context
 * @{
 */

/**
 * \brief Compute required buffer length for MAC 2/3 context.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] credential_material       ID_CRED_x and CRED_x encoder input.
 * \param[out] mac_context_length       On success, number of bytes that make up MAC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_comp_mac_context_length(
	const struct edhoc_context *edhoc_context,
	const struct edhoc_credential_material *credential_material,
	size_t *mac_context_length);

/**
 * \brief CBOR-encode items required by the MAC 2/3 context.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] credential_material       ID_CRED_x and CRED_x encoder input.
 * \param[out] mac_context              On success, generated MAC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_comp_mac_context(
	const struct edhoc_context *edhoc_context,
	const struct edhoc_credential_material *credential_material,
	struct mac_context *mac_context);

/**@}*/

/** \defgroup edhoc-common-sign-or-mac EDHOC common Signature_or_MAC
 * @{
 */

/**
 * \brief Compute required buffer length for MAC 2/3.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] mac_length               On success, number of bytes that make up
 *                                      MAC 2/3 length requirements.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_comp_mac_length(const struct edhoc_context *edhoc_context,
			  size_t *mac_length);

/**
 * \brief Compute MAC 2/3 buffer.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] mac_context               MAC context.
 * \param[out] mac                      Buffer where the generated MAC 2/3 is to be written.
 * \param mac_length                    Size of the \p mac buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_comp_mac(const struct edhoc_context *edhoc_context,
		   const struct mac_context *mac_context, uint8_t *mac,
		   size_t mac_length);

/**
 * \brief Compute required buffer length for Signature_or_MAC 2/3.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] sign_or_mac_length       On success, number of bytes that make up
 *                                      Signature_or_MAC 2/3 length requirements.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_comp_sign_or_mac_length(const struct edhoc_context *edhoc_context,
				  size_t *sign_or_mac_length);

/**
 * \brief Compute Signature_or_MAC 2/3 buffer.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] private_key_id            Handle of the local private key.
 * \param[in] mac_context               MAC context.
 * \param[in] mac                       Buffer containing the MAC 2/3.
 * \param[in] mac_len                   Size of the \p mac buffer in bytes.
 * \param[out] signature                Buffer where the generated
 *                                      Signature_or_MAC 2/3 is to be written.
 * \param signature_size                Size of the \p signature buffer in bytes.
 * \param[out] signature_length         On success, the number of bytes that make
 *                                      up the Signature_or_MAC 2/3.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_comp_sign_or_mac(const struct edhoc_context *edhoc_context,
			   const void *private_key_id,
			   const struct mac_context *mac_context,
			   const uint8_t *mac, size_t mac_len,
			   uint8_t *signature, size_t signature_size,
			   size_t *signature_length);

/**
 * \brief Verify Signature_or_MAC 2/3 buffer.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] mac_context               MAC context.
 * \param[in] public_key                Buffer containing authentication public key.
 * \param public_key_length             Size of the \p public_key buffer in bytes.
 * \param[in] signature                 Buffer containing Signature_or_MAC 2/3.
 * \param signature_length              Size of the \p signature buffer in bytes.
 * \param[in] mac                       Buffer containing MAC 2/3.
 * \param mac_length                    Size of the \p mac buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_verify_sign_or_mac(const struct edhoc_context *edhoc_context,
			     const struct mac_context *mac_context,
			     const uint8_t *public_key,
			     size_t public_key_length, const uint8_t *signature,
			     size_t signature_length, const uint8_t *mac,
			     size_t mac_length);

/**@}*/

#endif /* EDHOC_COMMON_INTERNAL_H */
