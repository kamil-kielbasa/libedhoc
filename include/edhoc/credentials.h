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
 * \brief COSE header parameter that identifies the credential in ID_CRED
 *        (RFC 9528: 3.5.3). Selects the active union member.
 */
enum edhoc_cose_header {
	/** Not set. A zeroed structure holds this value, so a missing label is
	 *  rejected instead of selecting a union member by accident. */
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
	/** Not set. A zeroed structure holds this value, so the format is
	 *  always a deliberate choice. */
	EDHOC_CREDENTIAL_FORMAT_NONE = 0,
	/** Opaque bytes, wrapped in a CBOR byte string. */
	EDHOC_CREDENTIAL_FORMAT_RAW,
	/** A CBOR item, embedded as it is. Admissible only for 'kid', whose
	 *  CRED may be a CCS or a CWT. */
	EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
};

_Static_assert(0 == EDHOC_CREDENTIAL_FORMAT_NONE,
	       "A zeroed credential must not name a format");

/**
 * \brief Local credential referenced by a key identifier
 *        (#EDHOC_COSE_HEADER_KID).
 *
 *        A 'kid' is a byte string (RFC 9528: Appendix C.3); the library applies
 *        the compact encoding of RFC 9528: 3.3.2 itself.
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
	/** Number of certificates, end-entity first, 1 to
	 *  #EDHOC_CREDENTIAL_X5CHAIN_CAPACITY. */
	size_t count;
	/** Certificates, in DER. */
	struct edhoc_buffer certificate[EDHOC_CREDENTIAL_X5CHAIN_CAPACITY];
};

/**
 * \brief Local credential referenced by a certificate fingerprint
 *        (#EDHOC_COSE_HEADER_X509_HASH).
 */
struct edhoc_credential_selected_x509_hash {
	/** Fingerprint algorithm, an integer or a name of at most
	 *  #EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN bytes. */
	struct edhoc_cbor_int_or_string algorithm;
	/** Fingerprint, at most #EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN
	 *  bytes. */
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
	/** Key identifier. It may arrive as a CBOR integer, which is only a
	 *  transport encoding of a one byte string (RFC 9528: 3.3.2); the
	 *  library resolves it before the callback runs. */
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
 *        (RFC 9528: 3.5). The library never takes ownership of a buffer and
 *        never frees one.
 */
struct edhoc_credentials {
	/**
	 * \brief Select the local party's authentication credential.
	 *
	 * Called while composing the message that carries it: message 2 for the
	 * Responder, message 3 for the Initiator. Populate \p selected, which
	 * the library zeroed beforehand. The library then builds ID_CRED and
	 * CRED and computes Signature_or_MAC with the referenced key
	 * (RFC 9528: 5.3.2, 5.4.2).
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
	 * Called once the peer's ID_CRED has been decoded: from message 2 on
	 * the Initiator, message 3 on the Responder. Look up what \p received
	 * points at, validate it against your trust policy — path building,
	 * trust anchors, revocation — and fill in \p trusted. EDHOC itself only
	 * proves possession of the private key (RFC 9528: 3.5, Appendix D).
	 *
	 * For #EDHOC_COSE_HEADER_X509_HASH the library does not check that the
	 * credential matches the fingerprint; that binding is enforced by the
	 * transcript, so a mismatch surfaces as an invalid Signature_or_MAC.
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
