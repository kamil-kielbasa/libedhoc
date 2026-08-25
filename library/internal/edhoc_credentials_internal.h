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
#include <edhoc_config.h>
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
struct id_cred_x;

/**
 * \brief Everything the ID_CRED_x and CRED_x encoders need, gathered in one
 *        place.
 *
 *        On compose the data comes from the local credentials; on process the
 *        identification comes from the peer and CRED from the credentials the
 *        application recognised. Both are funnelled through this type so the
 *        encoders exist once.
 */
struct edhoc_credential_material_asymmetric {
	/** Identification method; selects the active union member. */
	enum edhoc_cose_header label;
	/** Who performed the CBOR encoding: #EDHOC_CREDENTIAL_FORMAT_RAW means
	 *  the library wraps \p credential and \p kid, #EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED
	 *  means they are ready CBOR items and are embedded as they are. */
	enum edhoc_credential_format format;

	union {
		/** Valid for #EDHOC_COSE_HEADER_KID. A 'kid' is always a byte
		 *  string; the compact encoding of RFC 9528: 3.3.2 is applied by
		 *  the encoder. */
		struct edhoc_buffer kid;
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

/**
 * \brief Everything the ID_CRED_PSK, CRED_I and CRED_R encoders need
 *        (draft-ietf-lake-edhoc-psk: 3.1).
 *
 *        Method 4 identifies its credential by 'kid' only and names both
 *        credentials at once, so it has neither the label nor the X.509
 *        alternatives of \ref edhoc_credential_material_asymmetric.
 */
struct edhoc_credential_material_psk {
	/** ID_CRED_PSK, always a byte string; the compact encoding of
	 *  RFC 9528: 3.3.2 is applied by the encoder. */
	struct edhoc_buffer kid;
	/** Who performed the CBOR encoding of \p cred_i and \p cred_r. */
	enum edhoc_credential_format format;
	/** CRED_I. */
	struct edhoc_buffer cred_i;
	/** CRED_R. */
	struct edhoc_buffer cred_r;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-credentials-common EDHOC credentials common to every method
 *
 * ID_CRED_x decoding and credential validation. Decoding is shared by
 * message_2 (ID_CRED_R) and message_3 (ID_CRED_I); every field is a view into
 * the message being processed, so nothing is copied and nothing outlives the
 * call into \c authenticate_peer. On failure \p received is left untouched, so
 * a rejected ID_CRED_x never reaches the application with a partially
 * populated union.
 *
 * Validation runs right after each callback returns, so a malformed credential
 * is rejected before any field of it is used. The negotiated method selects
 * which member of the credential union has to be filled in.
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
int edhoc_credential_parse_map(const struct id_cred_x *id_cred_map,
			       struct edhoc_credential_received *received);

/**
 * \brief Validate the credentials the application returned from \c fetch.
 *
 * \param method                        Negotiated method; selects the member of
 *                                      \p selected that must be filled in.
 * \param[in] selected                  Local authentication credential.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_validate_selected(
	enum edhoc_method method,
	const struct edhoc_credential_selected *selected);

/**
 * \brief Validate what the application returned from \c authenticate_peer.
 *
 * \param method                        Negotiated method; selects the member of
 *                                      \p trusted that must be filled in.
 * \param[in] received                  Peer identification, as received.
 * \param[in] trusted                   Peer credential the application vouches for.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_validate_trusted(
	enum edhoc_method method,
	const struct edhoc_credential_received *received,
	const struct edhoc_credential_trusted *trusted);

/**@}*/

/** \defgroup edhoc-credentials-asymmetric EDHOC credentials of methods 0 to 3
 *
 * ID_CRED_x and CRED_x encoding, shared by message_2 (ID_CRED_R, CRED_R) and
 * message_3 (ID_CRED_I, CRED_I) on both the composing and the processing side.
 * Every entry point works on #edhoc_credential_material_asymmetric, so the
 * encoding rules have a single home.
 * @{
 */

/**
 * \brief Fill in the encoder input from the credential the application
 *        selected.
 *
 * \param[in] selected                  Local authentication credential.
 * \param[out] material                 On success, encoder input.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_asymmetric_material_from_selected(
	const struct edhoc_credential_selected *selected,
	struct edhoc_credential_material_asymmetric *material);

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
int edhoc_credential_asymmetric_material_from_trusted(
	const struct edhoc_credential_received *received,
	const struct edhoc_credential_trusted *trusted,
	struct edhoc_credential_material_asymmetric *material);

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
int edhoc_credential_asymmetric_id_cred_length(
	const struct edhoc_credential_material_asymmetric *material,
	size_t *length);

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
int edhoc_credential_asymmetric_cred_length(
	const struct edhoc_credential_material_asymmetric *material,
	size_t *length);

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
int edhoc_credential_asymmetric_encode_id_cred(
	const struct edhoc_credential_material_asymmetric *material,
	uint8_t *buffer, size_t buffer_length, size_t *length);

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
int edhoc_credential_asymmetric_encode_id_cred_compact(
	const struct edhoc_credential_material_asymmetric *material,
	uint8_t *buffer, size_t buffer_length, size_t *length);

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
int edhoc_credential_asymmetric_encode_cred(
	const struct edhoc_credential_material_asymmetric *material,
	uint8_t *buffer, size_t buffer_length, size_t *length);

/**@}*/

/** \defgroup edhoc-credentials-psk EDHOC credentials of method 4
 *
 * ID_CRED_PSK, CRED_I and CRED_R encoding, used by message_3 on both the
 * composing and the processing side. Every entry point works on
 * #edhoc_credential_material_psk.
 * @{
 */

/**
 * \brief Fill in the encoder input from the pre-shared key credential the
 *        application selected.
 *
 * \param[in] selected                  Local authentication credential.
 * \param[out] material                 On success, encoder input.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_psk_material_from_selected(
	const struct edhoc_credential_selected *selected,
	struct edhoc_credential_material_psk *material);

/**
 * \brief Fill in the encoder input for the pre-shared key credential the
 *        application vouched for.
 *
 * \param[in] received                  Peer identification, as received.
 * \param[in] trusted                   Credential the application vouches for.
 * \param[out] material                 On success, encoder input.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_psk_material_from_trusted(
	const struct edhoc_credential_received *received,
	const struct edhoc_credential_trusted *trusted,
	struct edhoc_credential_material_psk *material);

/**
 * \brief Compute the buffer length required by ID_CRED_PSK.
 *
 * \param[in] material                  Encoder input.
 * \param[out] length                   On success, required number of bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_psk_id_cred_length(
	const struct edhoc_credential_material_psk *material, size_t *length);

/**
 * \brief Compute the buffer length required by CRED_I and CRED_R together.
 *
 * \param[in] material                  Encoder input.
 * \param[out] length                   On success, required number of bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_psk_creds_length(
	const struct edhoc_credential_material_psk *material, size_t *length);

/**
 * \brief Encode ID_CRED_PSK, which draft-ietf-lake-edhoc-psk: 5.3.2 always
 *        carries in the compact form.
 *
 * \param[in] material                  Encoder input.
 * \param[out] buffer                   On success, ID_CRED_PSK.
 * \param buffer_length                 Size of \p buffer in bytes.
 * \param[out] length                   On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_psk_encode_id_cred(
	const struct edhoc_credential_material_psk *material, uint8_t *buffer,
	size_t buffer_length, size_t *length);

/**
 * \brief Encode CRED_I followed by CRED_R.
 *
 *        Method 4 always names the two together and in this order, in both
 *        external_aad and TH_4, so they are encoded in one pass.
 *
 * \param[in] material                  Encoder input.
 * \param[out] buffer                   On success, CRED_I and CRED_R.
 * \param buffer_length                 Size of \p buffer in bytes.
 * \param[out] cred_i_length            On success, bytes taken by CRED_I.
 * \param[out] cred_r_length            On success, bytes taken by CRED_R.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_credential_psk_encode_creds(
	const struct edhoc_credential_material_psk *material, uint8_t *buffer,
	size_t buffer_length, size_t *cred_i_length, size_t *cred_r_length);

/**@}*/

#endif /* EDHOC_CREDENTIALS_INTERNAL_H */
