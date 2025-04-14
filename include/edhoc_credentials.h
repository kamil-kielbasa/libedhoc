/**
 * \file    edhoc_credentials.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC authentication credentials interface.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CREDENTIALS_H
#define EDHOC_CREDENTIALS_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */

#ifndef CONFIG_LIBEDHOC_ENABLE
#error "Library has not been enabled."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID
#error "Lack of defined maximum length of authentication credentials key identifier in bytes."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG
#error "Lack of defined maximum length of authentication credentials hash algorithm in bytes."
#endif

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-credentials EDHOC interface credentials
 * @{
 */

/**
 * \brief CBOR encoding type where we can choose between integer or byte string.
 */
enum edhoc_encode_type {
	/** Encode as CBOR integer. */
	EDHOC_ENCODE_TYPE_INTEGER,
	/** Encode as CBOR byte string. */
	EDHOC_ENCODE_TYPE_BYTE_STRING,
};

/**
 * \brief Supported IANA COSE header labels.
 *
 * \ref https://www.iana.org/assignments/cose/cose.xhtml
 */
enum edhoc_cose_header {
	/** Any authentication credentials. */
	EDHOC_COSE_ANY = -65537,
	/** Authentication credentials identified by key identifier. */
	EDHOC_COSE_HEADER_KID = 4,
	/** Authentication credentials identified by an ordered chain of X.509 certificates. */
	EDHOC_COSE_HEADER_X509_CHAIN = 33,
	/** Authentication credentials identified by hash of an X.509 certificate. */
	EDHOC_COSE_HEADER_X509_HASH = 34,
};

/**
 * \brief Key identifier authentication method.
 *
 * \section fetch-kid For fetch callback we need to fill:
 * - any type of credentials:           \p cred and \p cred_len.
 * - is credentials cborised:           \p cred_is_cbor.
 * - encoding type of key identifer:    \p encode_type.
 * - key identifier:                    \p key_id_int or
 *                                      \p key_id_bstr and \p key_id_bstr_length.
 *
 * \section verify-kid In verify callback we will receive:
 * - \p encode_type.
 * - \p key_id_int or
 *   \p key_id_bstr & \p key_id_bstr_length.
 *
 * If key id has been found in local storage, reference for \p cred and
 * \p cred_len needs to written for further EDHOC processing.
 */
struct edhoc_auth_cred_key_id {
	/** Credentials buffor. */
	const uint8_t *cred;
	/** Size of the \p cred buffer in bytes. */
	size_t cred_len;
	/** Is credentials cborised? E.g. CWT, CCS. */
	bool cred_is_cbor;

	/** Encoding type of key identifier. 
         *
         * It must follow representation of byte string identifiers described in RFC 9528: 3.3.2. */
	enum edhoc_encode_type encode_type;

	/** Key identifier as cbor integer. */
	int32_t key_id_int;

	/** Key identifier as cbor byte string buffer. */
	uint8_t key_id_bstr[CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID + 1];
	/** Size of the \p key_id_bstr buffer in bytes. */
	size_t key_id_bstr_length;
};

/**
 * \brief X.509 chain authentication method.
 *
 * \section fetch-x5chain For fetch callback we need to fill:
 * - number of certificates: \p nr_of_certs.
 * - certificates: \p cert.
 * - certificate lengths: \p cert_len.
 *
 * \section verify-x5chain For verify callback we will receive:
 * - number of certificates: \p nr_of_certs.
 * - certificates: \p cert.
 * - certificate lengths: \p cert_len.
 */
struct edhoc_auth_cred_x509_chain {
	/** Number of certificates in chain. */
	size_t nr_of_certs;
	/** Certificates references. */
	const uint8_t *cert[CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN];
	/** Sizes of the \p cert references in bytes. */
	size_t cert_len[CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN];
};

/**
 * \brief X.509 hash authentication method.
 *
 * \section fetch-x5t For fetch callback we need to fill:
 * - certificate:                               \p cert & \p cert_len.
 * - certificate fingerprint:                   \p cert_fp & \p cert_fp_len.
 * - encoding type of fingerprint algorithm:    \p encode_type.
 * - fingerprint algorithm:                     \p alg_int or
 *                                              \p alg_bstr & \p alg_bstr_length.
 *
 * \section verify-x5t In verify callback we will receive:
 * - \p cert_fp & \p cert_fp_len.
 * - \p encode_type.
 * - \p alg_int or
 *   \p alg_bstr & \p alg_bstr_length.
 *
 * If certificate fingerprint has been found in local storage, reference for
 * \p cert and \p cert_len needs to written for further EDHOC processing.
 */
struct edhoc_auth_cred_x509_hash {
	/** Certificate buffer. */
	const uint8_t *cert;
	/** Size of the \p cert buffer in bytes. */
	size_t cert_len;

	/** Certificate fingerprint buffer. */
	const uint8_t *cert_fp;
	/** Size of the \p cert_fp buffer in bytes. */
	size_t cert_fp_len;

	/** Encoding type of certificate fingerprint algorithm. */
	enum edhoc_encode_type encode_type;

	/** Fingerprint algorithm as cbor integer. */
	int32_t alg_int;

	/** Fingerprint algorithm as cbor byte string buffer. */
	uint8_t alg_bstr[CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG + 1];
	/** Size of the \p alg_bstr buffer in bytes. */
	size_t alg_bstr_length;
};

/**
 * \brief Any authentication credentials.
 *   
 * \note Application developer is responsible for correct
 *       CBOR encoding (compact if required) and decoding.
 */
struct edhoc_auth_cred_any {
	/** Buffer containing identification and optionally transport the credentials.
	 *  RFC 9528: 2. EDHOC Outline: ID_CRED_I & ID_CRED_R. */
	const uint8_t *id_cred;
	/** Size of the \p id_cred buffer in bytes. */
	size_t id_cred_len;

	/** Is compact encoding of ID_CRED ?
	 *  RFC 9528: 3.5.3.2. Compact Encoding of ID_CRED Fields for 'kid'. */
	bool is_id_cred_comp_enc;
	/** Encoding type of ID_CRED. */
	enum edhoc_encode_type encode_type;

	/** Buffer containing compact encoded identification. */
	const uint8_t *id_cred_comp_enc;
	/** Size of the \p id_cred_comp_enc buffer in bytes. */
	size_t id_cred_comp_enc_length;

	/** Buffer containing authentication credentials containing the public authentication keys.
	 *  RFC 9528: 2. EDHOC Outline: CRED_I & CRED_R. */
	const uint8_t *cred;
	/** Size of the \p cred buffer in bytes. */
	size_t cred_len;
};

/**
 * \brief Common structure for different authentication credentials methods.
 */
struct edhoc_auth_creds {
	/** Private signature or static DH key. */
	uint8_t priv_key_id[CONFIG_LIBEDHOC_KEY_ID_LEN];

	/** COSE IANA label. */
	enum edhoc_cose_header label;
	union {
		/** Key identifier authentication structure. */
		struct edhoc_auth_cred_key_id key_id;
		/** X.509 chain authentication structure. */
		struct edhoc_auth_cred_x509_chain x509_chain;
		/** X.509 hash authentication structure. */
		struct edhoc_auth_cred_x509_hash x509_hash;
		/** User defined authentication credentials structure. */
		struct edhoc_auth_cred_any any;
	};
};

/**
 * \brief Authentication credentials fetch callback.
 *
 * \param[in] user_context              User context.
 * \param[out] credentials              Authentication credentials handle.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_credentials_fetch_t)(void *user_context,
					 struct edhoc_auth_creds *credentials);

/**
 * \brief Authentication credentials verify callback.
 *
 * \param[in] user_context              User context.
 * \param[in,out] credentials           Peer authentication credentials handle.
 * \param[out] public_key_reference     Pointer address where the public key address is to be written.
 * \param[out] public_key_length        On success, the number of bytes that make up the public key.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_credentials_verify_t)(void *user_context,
					  struct edhoc_auth_creds *credentials,
					  const uint8_t **public_key_reference,
					  size_t *public_key_length);

/**
 * \brief Bind structure for authentication credentials.
 */
struct edhoc_credentials {
	/** Authentication credentials fetch callback. */
	edhoc_credentials_fetch_t fetch;
	/** Authentication credentials verify callback. */
	edhoc_credentials_verify_t verify;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**@}*/

#endif /* EDHOC_CREDENTIALS_H */
