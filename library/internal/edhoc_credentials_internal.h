/**
 * \file    edhoc_credentials_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC authentication credentials:
 *          - ID_CRED_x decoding.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CREDENTIALS_INTERNAL_H
#define EDHOC_CREDENTIALS_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* EDHOC headers: */
#include <edhoc/credentials.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */

/** Longest CBOR byte string header for a key identifier: one byte for the
 *  major type when the length is below 24, two bytes above it. */
#define EDHOC_CREDENTIAL_KID_CBOR_HEADER_MAX_LEN (2)

_Static_assert(EDHOC_CREDENTIAL_KID_MAX_LEN <= UINT8_MAX,
	       "a longer key identifier needs a longer CBOR header");

/** Longest compact ID_CRED_x (RFC 9528: 3.5.3.2): the CBOR encoding of the
 *  key identifier, header included. */
#define EDHOC_CREDENTIAL_KID_COMPACT_MAX_LEN \
	(EDHOC_CREDENTIAL_KID_MAX_LEN +      \
	 EDHOC_CREDENTIAL_KID_CBOR_HEADER_MAX_LEN)

/* Types and type definitions ---------------------------------------------- */

/** ID_CRED_x COSE header map, defined by the CBOR backend. */
struct map;

/**
 * \brief Everything the ID_CRED_x and CRED_x encoders need, gathered in one
 *        place.
 *
 *        On compose the data comes from the local credentials; on process the
 *        identification comes from the peer and CRED from the credentials the
 *        application recognised. Both are funnelled through this type so the
 *        encoders exist once.
 */
struct edhoc_credential_material {
	/** Identification method; selects the active union member. */
	enum edhoc_cose_header label;
	/** Who performed the CBOR encoding: #EDHOC_CREDENTIAL_FORMAT_RAW means
	 *  the library wraps \p credential and \p kid, #EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED
	 *  means they are ready CBOR items and are embedded as they are. */
	enum edhoc_credential_format format;

	union {
		/** Valid for #EDHOC_COSE_HEADER_KID. */
		struct edhoc_cbor_int_or_string kid;
		/** Valid for #EDHOC_COSE_HEADER_X509_CHAIN. */
		struct {
			/** Number of certificates in the chain. */
			size_t count;
			/** Certificates, end-entity first. */
			struct edhoc_buffer
				certificate[EDHOC_CREDENTIAL_X5CHAIN_CAPACITY];
		} x509_chain;
		/** Valid for #EDHOC_COSE_HEADER_X509_HASH. */
		struct {
			/** Fingerprint algorithm. */
			struct edhoc_cbor_int_or_string algorithm;
			/** Certificate fingerprint. */
			struct edhoc_buffer fingerprint;
		} x509_hash;
	};

	/** CRED_x. */
	struct edhoc_buffer credential;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-credentials-decode EDHOC ID_CRED_x decoding
 *
 * Shared by message_2 (ID_CRED_R) and message_3 (ID_CRED_I). Every field is a
 * view into the message being processed, so nothing is copied and nothing
 * outlives the call into \c authenticate_peer. On failure \p received is left
 * untouched, so a rejected ID_CRED_x never reaches the application with a
 * partially populated union.
 * @{
 */

/**
 * \brief Decode ID_CRED_x carried as a bare CBOR integer, i.e. a 'kid' in the
 *        compact encoding (RFC 9528: 3.5.3.2).
 *
 *        The integer is a transport encoding of a one-byte key identifier
 *        (RFC 9528: 3.3.2), so the byte it stands for is restored into
 *        \p key_id_byte, which must outlive \p received.
 *
 * \param key_id                        Key identifier.
 * \param[out] key_id_byte              On success, the restored key identifier.
 * \param[out] received                 On success, peer identification.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_parse_kid_int(int32_t key_id, uint8_t *key_id_byte,
				   struct edhoc_credential_received *received);

/**
 * \brief Decode ID_CRED_x carried as a bare CBOR byte string, i.e. a 'kid' in
 *        the compact encoding (RFC 9528: 3.5.3.2).
 *
 * \param[in] key_id                    Key identifier.
 * \param key_id_length                 Length of \p key_id in bytes.
 * \param[out] received                 On success, peer identification.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_parse_kid_bstr(const uint8_t *key_id, size_t key_id_length,
				    struct edhoc_credential_received *received);

/**
 * \brief Decode ID_CRED_x carried as a COSE header map.
 *
 *        Exactly one supported header parameter must be present: 'x5chain' or
 *        'x5t'. A 'kid' in map form is rejected, see RFC 9528: 3.5.3.2.
 *
 * \param[in] id_cred_map               Decoded ID_CRED_x map.
 * \param[out] received                 On success, peer identification.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_parse_map(const struct map *id_cred_map,
			       struct edhoc_credential_received *received);

/**@}*/

/** \defgroup edhoc-credentials-validate EDHOC authentication credentials validation
 *
 * The application fills the credential structures, and their contents drive
 * both the ID_CRED_x / CRED_x encoders and the size of the MAC context. These
 * checks run right after each callback returns, so a malformed credential is
 * rejected before any field of it is used.
 * @{
 */

/**
 * \brief Validate the credentials the application returned from \c fetch.
 *
 * \param[in] credentials               Local authentication credentials.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_validate_credential_fetched(
	const struct edhoc_auth_credentials *credentials);

/**
 * \brief Validate what the application returned from \c authenticate_peer.
 *
 * \param[in] received                  Peer identification, as received.
 * \param[in] trusted                   Peer credential the application vouches for.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_validate_trusted(
	const struct edhoc_credential_received *received,
	const struct edhoc_credential_trusted *trusted);

/**@}*/

/** \defgroup edhoc-credentials-encode EDHOC ID_CRED_x and CRED_x encoding
 *
 * Shared by message_2 (ID_CRED_R, CRED_R) and message_3 (ID_CRED_I, CRED_I),
 * on both the composing and the processing side. Every entry point works on
 * #edhoc_credential_material, so the encoding rules have a single home.
 * @{
 */

/**
 * \brief Fill in the encoder input from the credentials the application
 *        returned.
 *
 * \param[in] credentials               Authentication credentials.
 * \param[out] material                 On success, encoder input.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_material_from_auth(
	const struct edhoc_auth_credentials *credentials,
	struct edhoc_credential_material *material);

/**
 * \brief Fill in the encoder input for the peer, from what was received and
 *        what the application vouched for.
 *
 * \param[in] received                  Peer identification, as received.
 * \param[in] trusted                   Peer credential the application vouches for.
 * \param[out] material                 On success, encoder input.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_material_from_trusted(
	const struct edhoc_credential_received *received,
	const struct edhoc_credential_trusted *trusted,
	struct edhoc_credential_material *material);

/**
 * \brief Compute the buffer length required by ID_CRED_x.
 *
 * \param[in] material                  Encoder input.
 * \param[out] length                   On success, required number of bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_id_cred_length(
	const struct edhoc_credential_material *material, size_t *length);

/**
 * \brief Compute the buffer length required by CRED_x.
 *
 * \param[in] material                  Encoder input.
 * \param[out] length                   On success, required number of bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_cred_length(
	const struct edhoc_credential_material *material, size_t *length);

/**
 * \brief Encode ID_CRED_x as a COSE header map.
 *
 * \param[in] material                  Encoder input.
 * \param[out] buffer                   On success, ID_CRED_x.
 * \param buffer_length                 Size of \p buffer in bytes.
 * \param[out] length                   On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_encode_id_cred(
	const struct edhoc_credential_material *material, uint8_t *buffer,
	size_t buffer_length, size_t *length);

/**
 * \brief Encode ID_CRED_x in the compact form, i.e. the bare 'kid'
 *        (RFC 9528: 3.5.3.2).
 *
 *        Only #EDHOC_COSE_HEADER_KID qualifies; for any other label the
 *        compact form does not exist and \p length is set to zero.
 *
 * \param[in] material                  Encoder input.
 * \param[out] buffer                   On success, compact ID_CRED_x.
 * \param buffer_length                 Size of \p buffer in bytes.
 * \param[out] length                   On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_encode_id_cred_compact(
	const struct edhoc_credential_material *material, uint8_t *buffer,
	size_t buffer_length, size_t *length);

/**
 * \brief Encode CRED_x.
 *
 * \param[in] material                  Encoder input.
 * \param[out] buffer                   On success, CRED_x.
 * \param buffer_length                 Size of \p buffer in bytes.
 * \param[out] length                   On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_encode_cred(
	const struct edhoc_credential_material *material, uint8_t *buffer,
	size_t buffer_length, size_t *length);

/**@}*/

#endif /* EDHOC_CREDENTIALS_INTERNAL_H */
