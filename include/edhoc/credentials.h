/**
 * \file    credentials.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC authentication credentials interface (RFC 9528: 3.5).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CREDENTIALS_H
#define EDHOC_CREDENTIALS_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */

#ifndef CONFIG_LIBEDHOC_ENABLE
#error "Library has not been enabled."
#endif /* CONFIG_LIBEDHOC_ENABLE */

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID
#error "Lack of defined maximum length of authentication credentials key identifier in bytes."
#endif /* CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID */

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN
#error "Lack of defined maximum number of certificates in an X.509 chain."
#endif /* CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN */

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG
#error "Lack of defined maximum length of authentication credentials hash algorithm in bytes."
#endif /* CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG */

#ifndef CONFIG_LIBEDHOC_KEY_ID_LEN
#error "Lack of defined length of private key identifier in bytes."
#endif /* CONFIG_LIBEDHOC_KEY_ID_LEN */

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-credentials EDHOC authentication credentials interface
 * @{
 */

/**
 * \brief CBOR encoding of an identifier: as an integer or as a byte string.
 */
enum edhoc_encode_type {
	/** Encode as CBOR integer. */
	EDHOC_ENCODE_TYPE_INTEGER,
	/** Encode as CBOR byte string. */
	EDHOC_ENCODE_TYPE_BYTE_STRING,
};

/**
 * \brief How the authentication credential is identified in ID_CRED.
 *
 *        Selects the COSE header parameter used in ID_CRED_I / ID_CRED_R, and
 *        thus which member of the \ref edhoc_auth_credentials union is active
 *        and how the credential is referenced or transported (RFC 9528: 3.5.3).
 */
enum edhoc_cose_header {
	/** User-defined identification; the application encodes and decodes
	 *  ID_CRED itself (\ref edhoc_auth_credential_custom). */
	EDHOC_COSE_HEADER_CUSTOM = -65537,
	/** COSE 'kid' (label 4): the credential is referenced by a key
	 *  identifier and is not transported; both parties must already hold it
	 *  (\ref edhoc_auth_credential_key_id). */
	EDHOC_COSE_HEADER_KID = 4,
	/** COSE 'x5chain' (label 33): an ordered chain of X.509 certificates
	 *  carried by value (\ref edhoc_auth_credential_x509_chain). */
	EDHOC_COSE_HEADER_X509_CHAIN = 33,
	/** COSE 'x5t' (label 34): a hash (thumbprint) of an X.509 certificate;
	 *  the certificate is looked up by that hash
	 *  (\ref edhoc_auth_credential_x509_hash). */
	EDHOC_COSE_HEADER_X509_HASH = 34,
};

/**
 * \brief Credential referenced by a COSE 'kid' key identifier
 *        (#EDHOC_COSE_HEADER_KID, RFC 9528: 3.5.3).
 *
 *        The credential itself is not carried in the EDHOC message; only its
 *        key identifier is sent, so both parties must already hold the
 *        credential out of band.
 *
 * \par On fetch, populate:
 * - the credential and its length: \p credential, \p credential_length;
 * - whether the credential is CBOR-encoded (e.g. CWT, CCS):
 *   \p is_credential_cbor_encoded;
 * - the key-identifier encoding: \p encode_type;
 * - the key identifier: \p key_id_int, or \p key_id_bstr.value with
 *   \p key_id_bstr.length.
 *
 * \par On verify, you receive:
 * - the key-identifier encoding: \p encode_type;
 * - the key identifier: \p key_id_int, or \p key_id_bstr.value with
 *   \p key_id_bstr.length.
 *
 * On verify, once the referenced credential is found in local storage, set
 * \p credential and \p credential_length to it for the rest of EDHOC
 * processing.
 */
struct edhoc_auth_credential_key_id {
	/** Credential buffer. */
	const uint8_t *credential;
	/** Size of the \p credential buffer in bytes. */
	size_t credential_length;
	/** Is the credential CBOR-encoded? E.g. CWT, CCS. */
	bool is_credential_cbor_encoded;

	/** Encoding of the key identifier. It must follow the representation of
	 *  byte string identifiers described in RFC 9528: 3.3.2. */
	enum edhoc_encode_type encode_type;

	/** Key identifier, selected by \p encode_type: \p key_id_int when
	 *  #EDHOC_ENCODE_TYPE_INTEGER, otherwise \p key_id_bstr. */
	union {
		/** Key identifier as a CBOR integer
		 *  (#EDHOC_ENCODE_TYPE_INTEGER). */
		int32_t key_id_int;
		/** Key identifier as a CBOR byte string
		 *  (#EDHOC_ENCODE_TYPE_BYTE_STRING). */
		struct {
			/** Byte string buffer. */
			uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID +
				      1];
			/** Size of the \p value buffer in bytes. */
			size_t length;
		} key_id_bstr;
	};
};

/**
 * \brief Credential carried as an X.509 certificate chain
 *        (#EDHOC_COSE_HEADER_X509_CHAIN, RFC 9528: 3.5.3).
 *
 *        The ordered chain (end-entity certificate first) is transported by
 *        value in the EDHOC message.
 *
 * \par On fetch, populate:
 * - the number of certificates: \p certificate_count;
 * - the certificate buffers: \p certificate;
 * - their lengths: \p certificate_length.
 *
 * \par On verify, you receive:
 * - the same fields (\p certificate_count, \p certificate,
 *   \p certificate_length), which you validate per your trust policy (path
 *   building, trust anchors, revocation).
 */
struct edhoc_auth_credential_x509_chain {
	/** Number of certificates in the chain. */
	size_t certificate_count;
	/** Certificate references. One slot is spare so the array stays valid
	 *  when CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN is 0; the usable
	 *  capacity is ARRAY_SIZE() - 1. */
	const uint8_t
		*certificate[CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN + 1];
	/** Sizes of the \p certificate references in bytes. */
	size_t certificate_length[CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN +
				  1];
};

/**
 * \brief Credential referenced by an X.509 certificate hash
 *        (#EDHOC_COSE_HEADER_X509_HASH, RFC 9528: 3.5.3).
 *
 *        Only a hash (thumbprint) of the end-entity certificate is sent; the
 *        certificate itself is looked up locally by that hash.
 *
 * \par On fetch, populate:
 * - the certificate and its length: \p certificate, \p certificate_length;
 * - the certificate fingerprint: \p certificate_fingerprint,
 *   \p certificate_fingerprint_length;
 * - the fingerprint-algorithm encoding: \p encode_type;
 * - the fingerprint algorithm: \p algorithm_int, or \p algorithm_bstr.value
 *   with \p algorithm_bstr.length.
 *
 * \par On verify, you receive:
 * - the certificate fingerprint: \p certificate_fingerprint,
 *   \p certificate_fingerprint_length;
 * - the fingerprint-algorithm encoding: \p encode_type;
 * - the fingerprint algorithm: \p algorithm_int, or \p algorithm_bstr.value
 *   with \p algorithm_bstr.length.
 *
 * On verify, once the certificate matching the fingerprint is found, set
 * \p certificate and \p certificate_length to it for the rest of EDHOC
 * processing.
 */
struct edhoc_auth_credential_x509_hash {
	/** Certificate buffer. */
	const uint8_t *certificate;
	/** Size of the \p certificate buffer in bytes. */
	size_t certificate_length;

	/** Certificate fingerprint buffer. */
	const uint8_t *certificate_fingerprint;
	/** Size of the \p certificate_fingerprint buffer in bytes. */
	size_t certificate_fingerprint_length;

	/** Encoding of the certificate fingerprint algorithm. */
	enum edhoc_encode_type encode_type;

	/** Fingerprint algorithm, selected by \p encode_type: \p algorithm_int
	 *  when #EDHOC_ENCODE_TYPE_INTEGER, otherwise \p algorithm_bstr. */
	union {
		/** Fingerprint algorithm as a CBOR integer
		 *  (#EDHOC_ENCODE_TYPE_INTEGER). */
		int32_t algorithm_int;
		/** Fingerprint algorithm as a CBOR byte string
		 *  (#EDHOC_ENCODE_TYPE_BYTE_STRING). */
		struct {
			/** Byte string buffer. */
			uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG + 1];
			/** Size of the \p value buffer in bytes. */
			size_t length;
		} algorithm_bstr;
	};
};

/**
 * \brief User-defined authentication credential
 *        (#EDHOC_COSE_HEADER_CUSTOM, RFC 9528: 3.5.3).
 *
 *        The application chooses how ID_CRED and the credential are identified,
 *        transported and (de)serialized, populating the fields below on fetch
 *        and receiving them back on verify.
 *
 * \note The application is responsible for the correct CBOR encoding (compact
 *       when required) and decoding.
 */
struct edhoc_auth_credential_custom {
	/** ID_CRED buffer: identifies and optionally transports the credential
	 *  (RFC 9528: 2. EDHOC Outline — ID_CRED_I & ID_CRED_R). */
	const uint8_t *id_credential;
	/** Size of the \p id_credential buffer in bytes. */
	size_t id_credential_length;

	/** Is ID_CRED in compact encoding? (RFC 9528: 3.5.3.2. Compact Encoding
	 *  of ID_CRED Fields for 'kid'). */
	bool is_id_credential_compact_encoded;
	/** Encoding of the compact ID_CRED. */
	enum edhoc_encode_type encode_type;

	/** Compact-encoded ID_CRED buffer. */
	const uint8_t *id_credential_compact;
	/** Size of the \p id_credential_compact buffer in bytes. */
	size_t id_credential_compact_length;

	/** CRED buffer: the authentication credential carrying the public
	 *  authentication key (RFC 9528: 2. EDHOC Outline — CRED_I & CRED_R). */
	const uint8_t *credential;
	/** Size of the \p credential buffer in bytes. */
	size_t credential_length;
};

/**
 * \brief An EDHOC authentication credential (tagged union over the methods).
 *
 *        \p label selects the identification method and thus which union member
 *        is active; \p private_key_id is the key-store handle of the local
 *        party's private authentication key (a signature or static-DH key).
 */
struct edhoc_auth_credentials {
	/** Key-store handle of the private signature or static-DH
	 *  authentication key. */
	uint8_t private_key_id[CONFIG_LIBEDHOC_KEY_ID_LEN];

	/** Identification method; selects the active union member. */
	enum edhoc_cose_header label;
	union {
		/** Key identifier authentication structure. */
		struct edhoc_auth_credential_key_id key_id;
		/** X.509 chain authentication structure. */
		struct edhoc_auth_credential_x509_chain x509_chain;
		/** X.509 hash authentication structure. */
		struct edhoc_auth_credential_x509_hash x509_hash;
		/** User-defined authentication credential structure
		 *  (selected by #EDHOC_COSE_HEADER_CUSTOM). */
		struct edhoc_auth_credential_custom custom;
	};
};

/**
 * \brief Authentication credentials interface, bound with
 *        \ref edhoc_bind_credentials.
 *
 *        EDHOC delegates credential handling to the application (RFC 9528: 3.5):
 *        the library calls \p fetch to obtain the local credential to send, and
 *        \p verify to authenticate the peer's received credential.
 */
struct edhoc_credentials {
	/**
	 * \brief Provide the local party's authentication credential.
	 *
	 * Called while composing the message that carries the local credential
	 * (message 2 for the Responder, message 3 for the Initiator). Populate
	 * \p local_credentials: set \p label (identification method),
	 * \p private_key_id (handle of the local private authentication key) and
	 * the matching union member. The library then builds ID_CRED and CRED
	 * and computes Signature_or_MAC with the referenced key (RFC 9528: 3.5,
	 * 5.3.2, 5.4.2).
	 *
	 * \param[in] user_context              User context.
	 * \param[out] local_credentials        Local authentication credential to populate.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*fetch)(void *user_context,
		     struct edhoc_auth_credentials *local_credentials);

	/**
	 * \brief Authenticate the peer's authentication credential.
	 *
	 * Called after the peer's ID_CRED has been received and decoded (from
	 * message 2 on the Initiator, message 3 on the Responder). Use the
	 * identification in \p peer_credentials to locate and validate the peer
	 * credential per your trust policy — e.g. certificate path and
	 * trust-anchor validation, revocation, or a key-identifier lookup — and
	 * return a reference to the peer's public authentication key so the
	 * library can verify Signature_or_MAC. EDHOC itself only proves
	 * possession of the private key; all other credential validation is the
	 * application's responsibility (RFC 9528: 3.5, Appendix D).
	 *
	 * \param[in] user_context              User context.
	 * \param[in,out] peer_credentials      Peer credential: identification in, resolved credential out.
	 * \param[out] public_key_reference     On success, set to the peer's public authentication key.
	 * \param[out] public_key_length        On success, the length of the public key in bytes.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*verify)(void *user_context,
		      struct edhoc_auth_credentials *peer_credentials,
		      const uint8_t **public_key_reference,
		      size_t *public_key_length);
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**@}*/

#endif /* EDHOC_CREDENTIALS_H */
