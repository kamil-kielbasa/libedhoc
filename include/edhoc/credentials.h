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
#include <edhoc_config.h>
#endif

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* EDHOC headers: */
#include <edhoc/types.h>
#include <edhoc/values.h>

/* Defines ----------------------------------------------------------------- */

/** Maximum length of a COSE 'kid' key identifier in bytes. */
#define EDHOC_CREDENTIAL_KID_MAX_LEN CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID

/** Capacity of a COSE 'x5chain' certificate chain, in certificates. */
#define EDHOC_CREDENTIAL_X5CHAIN_CAPACITY \
	CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN

/** Maximum length of a COSE 'x5t' hash algorithm name in bytes. Applies to the
 *  text form only; the integer form carries no buffer. */
#define EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN (32)

/** Maximum length of a COSE 'x5t' certificate fingerprint in bytes, sized for
 *  the longest hash COSE defines for a certificate thumbprint. */
#define EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN (64)

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-credentials EDHOC authentication credentials interface
 * @{
 */

/**
 * \brief Encoding of a CBOR item that is either a number or a string.
 */
enum edhoc_encode_type {
	/** CBOR integer. */
	EDHOC_ENCODE_TYPE_INTEGER,
	/** CBOR byte string or text string, depending on the field. */
	EDHOC_ENCODE_TYPE_STRING,
};

/**
 * \brief A CBOR item that is either a number or a string.
 */
struct edhoc_cbor_int_or_string {
	/** Which member of the union is valid. */
	enum edhoc_encode_type encode_type;

	union {
		/** Valid for #EDHOC_ENCODE_TYPE_INTEGER. */
		int32_t integer;
		/** Valid for #EDHOC_ENCODE_TYPE_STRING. */
		struct edhoc_buffer string;
	};
};

/**
 * \brief COSE header parameter that identifies the credential in ID_CRED
 *        (RFC 9528: 3.5.3). Selects the active union member.
 */
enum edhoc_cose_header {
	/** Not set. A zeroed structure holds this value and is rejected. */
	EDHOC_COSE_HEADER_NONE = 0,
	/** 'kid' (4): credential referenced by a key identifier, not sent. */
	EDHOC_COSE_HEADER_KID = 4,
	/** 'x5chain' (33): X.509 certificate chain sent by value. */
	EDHOC_COSE_HEADER_X509_CHAIN = 33,
	/** 'x5t' (34): X.509 certificate referenced by a fingerprint. */
	EDHOC_COSE_HEADER_X509_HASH = 34,
};

_Static_assert(0 == EDHOC_COSE_HEADER_NONE,
	       "A zeroed credential must not name an identification method");

/**
 * \brief How CRED_I / CRED_R is serialized.
 */
enum edhoc_credential_format {
	/** Not set. A zeroed structure holds this value and is rejected. */
	EDHOC_CREDENTIAL_FORMAT_NONE = 0,
	/** Opaque bytes, wrapped in a CBOR byte string. */
	EDHOC_CREDENTIAL_FORMAT_RAW,
	/** A ready CBOR item, embedded as it is. Admissible only for 'kid'. */
	EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
};

_Static_assert(0 == EDHOC_CREDENTIAL_FORMAT_NONE,
	       "A zeroed credential must not name a format");

/**
 * \brief Local credential referenced by a key identifier
 *        (#EDHOC_COSE_HEADER_KID).
 */
struct edhoc_credential_selected_kid {
	/** Key identifier, at most #EDHOC_CREDENTIAL_KID_MAX_LEN bytes. */
	struct edhoc_buffer identifier;
	/** CRED_I / CRED_R, held out of band by both parties. */
	struct edhoc_buffer credential;
	/** Serialization of \p credential. */
	enum edhoc_credential_format format;
};

/**
 * \brief Local credential sent as a certificate chain
 *        (#EDHOC_COSE_HEADER_X509_CHAIN).
 *
 *        CRED_I / CRED_R is \p certificate[0], so the library takes it itself.
 */
struct edhoc_credential_selected_x509_chain {
	/** Number of certificates, 1 to #EDHOC_CREDENTIAL_X5CHAIN_CAPACITY. */
	size_t count;
	/** Certificates, in DER, end-entity first. */
	struct edhoc_buffer certificate[EDHOC_CREDENTIAL_X5CHAIN_CAPACITY];
};

/**
 * \brief Local credential referenced by a certificate fingerprint
 *        (#EDHOC_COSE_HEADER_X509_HASH).
 */
struct edhoc_credential_selected_x509_hash {
	/** Fingerprint algorithm; a name is at most
	 *  #EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN bytes. */
	struct edhoc_cbor_int_or_string algorithm;
	/** Fingerprint, at most #EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN bytes. */
	struct edhoc_buffer fingerprint;
	/** CRED_I / CRED_R: the certificate in DER, not sent. */
	struct edhoc_buffer certificate;
};

/**
 * \brief The local party's authentication credential, filled in by
 *        \c select_local.
 *
 *        Fill in \p private_key_id, \p label and every field of the union
 *        member \p label names.
 *
 * \warning The buffers must stay readable until the composing call returns.
 */
struct edhoc_credential_selected {
	/** Key-store handle of the private signature or static-DH key. */
	uint8_t private_key_id[CONFIG_LIBEDHOC_KEY_ID_LEN];

	/** Identification method; selects the active union member. */
	enum edhoc_cose_header label;

	union {
		/** Valid for #EDHOC_COSE_HEADER_KID. */
		struct edhoc_credential_selected_kid kid;
		/** Valid for #EDHOC_COSE_HEADER_X509_CHAIN. */
		struct edhoc_credential_selected_x509_chain x509_chain;
		/** Valid for #EDHOC_COSE_HEADER_X509_HASH. */
		struct edhoc_credential_selected_x509_hash x509_hash;
	};
};

/**
 * \brief Key identifier received from the peer (#EDHOC_COSE_HEADER_KID).
 */
struct edhoc_credential_received_kid {
	/** Key identifier, the same byte string \c select_local presented on the
	 *  other side. */
	struct edhoc_buffer identifier;
};

/**
 * \brief Certificate chain received from the peer
 *        (#EDHOC_COSE_HEADER_X509_CHAIN).
 */
struct edhoc_credential_received_x509_chain {
	/** Number of certificates, end-entity first. */
	size_t count;
	/** Certificates, in DER. */
	struct edhoc_buffer certificate[EDHOC_CREDENTIAL_X5CHAIN_CAPACITY];
};

/**
 * \brief Certificate fingerprint received from the peer
 *        (#EDHOC_COSE_HEADER_X509_HASH).
 */
struct edhoc_credential_received_x509_hash {
	/** Fingerprint algorithm. */
	struct edhoc_cbor_int_or_string algorithm;
	/** Certificate fingerprint. */
	struct edhoc_buffer fingerprint;
};

/**
 * \brief ID_CRED_I / ID_CRED_R as received from the peer, passed to
 *        \c authenticate_peer.
 *
 * \warning Every buffer points into the message being processed. It may be
 *          handed straight back in #edhoc_credential_trusted, but stops being
 *          valid once the processing call returns.
 */
struct edhoc_credential_received {
	/** Identification method; selects the active union member. Never
	 *  #EDHOC_COSE_HEADER_NONE. */
	enum edhoc_cose_header label;

	union {
		/** Valid for #EDHOC_COSE_HEADER_KID. */
		struct edhoc_credential_received_kid kid;
		/** Valid for #EDHOC_COSE_HEADER_X509_CHAIN. */
		struct edhoc_credential_received_x509_chain x509_chain;
		/** Valid for #EDHOC_COSE_HEADER_X509_HASH. */
		struct edhoc_credential_received_x509_hash x509_hash;
	};
};

/**
 * \brief The peer credential the application vouches for, returned from
 *        \c authenticate_peer.
 *
 *        Filling this in asserts that the application resolved the identifier
 *        and validated the credential against its own trust policy
 *        (RFC 9528: Appendix D). Fill in all three fields; for
 *        #EDHOC_COSE_HEADER_X509_CHAIN, CRED is the received end-entity
 *        certificate handed back.
 *
 * \warning The buffers must stay readable until the processing call returns,
 *          so never the callback's stack. A view from
 *          #edhoc_credential_received satisfies this.
 */
struct edhoc_credential_trusted {
	/** CRED_I / CRED_R. */
	struct edhoc_buffer credential;
	/** Serialization of \p credential. */
	enum edhoc_credential_format format;
	/** Peer authentication key, in the form the cipher suite expects. */
	struct edhoc_buffer public_key;
};

/**
 * \brief Authentication credentials interface, bound with
 *        \ref edhoc_bind_credentials.
 *
 *        EDHOC delegates credential handling to the application
 *        (RFC 9528: 3.5). Both entries are mandatory. The library never takes
 *        ownership of a buffer and never frees one.
 */
struct edhoc_credentials {
	/**
	 * \brief Select the local party's authentication credential.
	 *
	 * Called while composing the message that carries it:
	 * - the Responder, composing message 2 (RFC 9528: 5.3.2);
	 * - the Initiator, composing message 3 (RFC 9528: 5.4.2).
	 *
	 * The library then builds ID_CRED and CRED from \p selected and computes
	 * Signature_or_MAC with the referenced key.
	 *
	 * \param[in] user_context              User context.
	 * \param[in] call_context              Parameters of the ongoing session.
	 * \param[out] selected                 Credential to populate.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*select_local)(void *user_context,
			    const struct edhoc_call_context *call_context,
			    struct edhoc_credential_selected *selected);

	/**
	 * \brief Authenticate the peer's authentication credential.
	 *
	 * Called once the peer's ID_CRED has been decoded:
	 * - the Initiator, processing message 2 (ID_CRED_R);
	 * - the Responder, processing message 3 (ID_CRED_I).
	 *
	 * Look up what \p received points at, validate it against your trust
	 * policy — path building, trust anchors, revocation — and fill in
	 * \p trusted. EDHOC itself only proves possession of the private key
	 * (RFC 9528: 3.5, Appendix D).
	 *
	 * \param[in] user_context              User context.
	 * \param[in] call_context              Parameters of the ongoing session.
	 * \param[in] received                  Peer identification, as received.
	 * \param[out] trusted                  Credential to authenticate with.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure (\ref edhoc-error-codes).
	 */
	int (*authenticate_peer)(
		void *user_context,
		const struct edhoc_call_context *call_context,
		const struct edhoc_credential_received *received,
		struct edhoc_credential_trusted *trusted);
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**@}*/

#endif /* EDHOC_CREDENTIALS_H */
