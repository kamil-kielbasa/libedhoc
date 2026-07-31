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
#include <edhoc/types.h>

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

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN
#error "Lack of defined maximum number of certificates in an X.509 chain."
#endif /* CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN */

#ifndef CONFIG_LIBEDHOC_KEY_ID_LEN
#error "Lack of defined length of private key identifier in bytes."
#endif /* CONFIG_LIBEDHOC_KEY_ID_LEN */

/** Maximum length of a COSE 'kid' key identifier in bytes. RFC 9528 puts no
 *  bound on it; this one covers every identifier the reference cipher suites
 *  can produce, including a full SHA-256 thumbprint. */
#define EDHOC_CREDENTIAL_KID_MAX_LEN (32)

/** Capacity of a COSE 'x5chain' certificate chain, in certificates. */
#define EDHOC_CREDENTIAL_X5CHAIN_CAPACITY \
	CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN

/** Maximum length of a COSE 'x5t' hash algorithm name in bytes. Applies to the
 *  text form only; the integer form carries no buffer. Sized for the longest
 *  COSE algorithm name in the IANA registry. */
#define EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN (32)

/** Maximum length of a COSE 'x5t' certificate fingerprint in bytes. The longest
 *  hash COSE defines for a certificate thumbprint is SHA-512, so a longer
 *  fingerprint is rejected. */
#define EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN (64)

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-credentials EDHOC authentication credentials interface
 * @{
 */

/**
 * \brief How the authentication credential is identified in ID_CRED.
 *
 *        Selects the COSE header parameter used in ID_CRED_I / ID_CRED_R, and
 *        thus which member of the \ref edhoc_auth_credentials union is active
 *        and how the credential is referenced or transported (RFC 9528: 3.5.3).
 */
enum edhoc_cose_header {
	/** Not set. A zeroed structure holds this value, so leaving the label
	 *  out is rejected instead of silently selecting a union member. */
	EDHOC_COSE_HEADER_NONE = 0,
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

_Static_assert(0 == EDHOC_COSE_HEADER_NONE,
	       "A zeroed credential must not name an identification method");

/**
 * \brief How a credential is serialized.
 *
 *        The label fixes what is admissible: only a credential referenced by
 *        #EDHOC_COSE_HEADER_KID may be a CBOR item (a CWT or a CCS), because
 *        for the X.509 variants CRED is the DER certificate.
 */
enum edhoc_credential_format {
	/** Not set. A zeroed structure holds this value, so the format is
	 *  always a deliberate choice. */
	EDHOC_CREDENTIAL_FORMAT_NONE = 0,
	/** Opaque bytes, wrapped in a CBOR byte string. */
	EDHOC_CREDENTIAL_FORMAT_RAW,
	/** A CBOR item, embedded as it is. */
	EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
};

_Static_assert(0 == EDHOC_CREDENTIAL_FORMAT_NONE,
	       "A zeroed credential must not name a format");

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

	/** Encoding of the key identifier. It must follow the representation of
	 *  byte string identifiers described in RFC 9528: 3.3.2. */
	enum edhoc_encode_type encode_type;

	union {
		/** Key identifier as a CBOR integer
		 *  (#EDHOC_ENCODE_TYPE_INTEGER). */
		int32_t key_id_int;
		/** Key identifier as a CBOR byte string
		 *  (#EDHOC_ENCODE_TYPE_STRING). */
		struct {
			/** Byte string buffer. */
			uint8_t value[EDHOC_CREDENTIAL_KID_MAX_LEN];
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
	/** Number of certificates in the chain, at most
	 *  #EDHOC_CREDENTIAL_X5CHAIN_CAPACITY. */
	size_t certificate_count;
	/** Certificate references. */
	const uint8_t *certificate[EDHOC_CREDENTIAL_X5CHAIN_CAPACITY];
	/** Sizes of the \p certificate references in bytes. */
	size_t certificate_length[EDHOC_CREDENTIAL_X5CHAIN_CAPACITY];
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
		 *  (#EDHOC_ENCODE_TYPE_STRING). */
		struct {
			/** Byte string buffer. */
			uint8_t value[EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN];
			/** Size of the \p value buffer in bytes. */
			size_t length;
		} algorithm_bstr;
	};
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
	/** Serialization of the credential (CRED). Constrained by \p label:
	 *  #EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED is admissible only for
	 *  #EDHOC_COSE_HEADER_KID, whose CRED may be a CCS or a CWT. For the
	 *  X.509 variants CRED is the DER certificate, and the library fills the
	 *  format in on verify, since it is the one that knows that.
	 *
	 *  It says nothing about the identifier itself: ID_CRED_x is always
	 *  encoded by the library, following RFC 9528: 3.3.2. */
	enum edhoc_credential_format format;

	union {
		/** Key identifier authentication structure. */
		struct edhoc_auth_credential_key_id key_id;
		/** X.509 chain authentication structure. */
		struct edhoc_auth_credential_x509_chain x509_chain;
		/** X.509 hash authentication structure. */
		struct edhoc_auth_credential_x509_hash x509_hash;
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
