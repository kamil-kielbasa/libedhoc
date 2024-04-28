/**
 * \file    edhoc_credentials.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC authentication credentials interface.
 * \version 0.2
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CREDENTIALS_H
#define EDHOC_CREDENTIALS_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/**
 * \brief CBOR encoding type where we can choose between integer or byte string.
 */
enum edhoc_encode_type {
	EDHOC_ENCODE_TYPE_INTEGER,
	EDHOC_ENCODE_TYPE_BYTE_STRING,
};

/**
 * \brief Supported IANA COSE header labels.
 *
 * \ref https://www.iana.org/assignments/cose/cose.xhtml
 */
enum edhoc_cose_header {
	EDHOC_COSE_HEADER_KID = 4,
	EDHOC_COSE_HEADER_X509_CHAIN = 33,
	EDHOC_COSE_HEADER_X509_HASH = 34,
};

/**
 * \brief Key identifier authentication method.
 *
 * For fetch callback we need to fill:
 * - any type of credentials:           \p cred & \p cred_len.
 * - encoding type of key identifer:    \p encode_type.
 * - key identifier:                    \p key_id_int or
 *                                      \p key_id_bstr & \p key_id_bstr_length.
 *
 * In verify callback we will receive:
 * - \p encode_type.
 * - \p key_id_int or
 *   \p key_id_bstr & \p key_id_bstr_length.
 *
 * If key id has been found in local storage, reference for \p cred and
 * \p cred_len needs to written for further EDHOC processing.
 */
struct edhoc_auth_cred_key_id {
	const uint8_t *cred;
	size_t cred_len;

	enum edhoc_encode_type encode_type;

	int32_t key_id_int;

	uint8_t key_id_bstr[EDHOC_CRED_KEY_ID_LEN + 1];
	size_t key_id_bstr_length;
};

/**
 * \brief X509 chain authentication method.
 *
 * For fetch callback we need to fill:
 * - certificate: \p cert & \p cert_len.
 *
 * For verify callback we will receive peer certificate by value, not reference.
 */
struct edhoc_auth_cred_x509_chain {
	const uint8_t *cert;
	size_t cert_len;
};

/**
 * \brief X509 hash authentication method.
 *
 * For fetch callback we need to fill:
 * - certificate:                               \p cert & \p cert_len.
 * - certificate fingerprint:                   \p cert_fp & \p cert_fp_len.
 * - encoding type of fingerprint algorithm:    \p encode_type.
 * - fingerprint algorithm:                     \p alg_int or
 *                                              \p alg_bstr & \p alg_bstr_length.
 *
 * In verify callback we will receive:
 * - \p cert_fp & \p cert_fp_len.
 * - \p encode_type.
 * - \p alg_int or
 *   \p alg_bstr & \p alg_bstr_length.
 *
 * If certificate fingerprint has been found in local storage, reference for
 * \p cert and \p cert_len needs to written for further EDHOC processing.
 */
struct edhoc_auth_cred_x509_hash {
	const uint8_t *cert;
	size_t cert_len;

	const uint8_t *cert_fp;
	size_t cert_fp_len;

	enum edhoc_encode_type encode_type;

	int32_t alg_int;

	uint8_t alg_bstr[EDHOC_CRED_X509_HASH_ALG_LEN + 1];
	size_t alg_bstr_length;
};

/**
 * \brief Common structure for different authentication credentials methods.
 */
struct edhoc_auth_creds {
	uint8_t priv_key_id[EDHOC_KID_LEN];

	enum edhoc_cose_header label;
	union {
		struct edhoc_auth_cred_key_id key_id;
		struct edhoc_auth_cred_x509_chain x509_chain;
		struct edhoc_auth_cred_x509_hash x509_hash;
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
	edhoc_credentials_fetch_t fetch;
	edhoc_credentials_verify_t verify;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_CREDENTIALS_H */
