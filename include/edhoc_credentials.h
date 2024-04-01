/**
 * \file    edhoc_credentials.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC credentials interface.
 * \version 0.1
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
 * \brief Key ID authentication method.
 *
 * For fetch callback we need to fill:
 * - key identifier:            \p key_id & \p key_id_len.
 * - any type of credentials:   \p cred & \p cred_len.
 *
 * For verify callback we will receive:
 * - \p key_id & \p key_id_len.
 *
 * If key id has been found in local storage, reference for \p cred and
 * \p cred_len needs to written for further EDHOC processing.
 */
struct edhoc_auth_cred_key_id {
	const uint8_t *cred;
	size_t cred_len;

	uint8_t key_id[EDHOC_CRED_KEY_ID_LEN + 1];
	size_t key_id_len;
};

/**
 * \brief X509 hash authentication method.
 *
 * For fetch callback we need to fill:
 * - certificate:               \p cert & \p cert_len.
 * - certificate fingerprint:   \p cert_fp & \p cert_fp_len.
 * - fingerprint algorithm:     \p alg & \p alg_len.
 *
 * For verify callback we will receive:
 * - \p cert_fp & \p cert_fp_len.
 * - \p alg & \p alg_len.
 *
 * If certificate fingerprint has been found in local storage, reference for
 * \p cert and \p cert_len needs to written for further EDHOC processing.
 */
struct edhoc_auth_cred_x509_hash {
	const uint8_t *cert;
	size_t cert_len;

	const uint8_t *cert_fp;
	size_t cert_fp_len;

	uint8_t alg[EDHOC_CRED_X509_HASH_ALG_LEN + 1];
	size_t alg_len;
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
 * \brief Common structure for authentication credentials fetch & verify.
 *
 * Despite 
 */
struct edhoc_auth_creds {
	enum edhoc_cose_header label;

	uint8_t priv_key_id[EDHOC_KID_LEN];

	struct edhoc_auth_cred_key_id key_id;
	struct edhoc_auth_cred_x509_hash x509_hash;
	struct edhoc_auth_cred_x509_chain x509_chain;
};

/**
 * \brief Authentication credentials fetch callback.
 *
 * \param[in] user_ctx          User context.
 * \param[out] auth_cred        Handle for authentication credentials.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_credentials_fetch_t)(void *user_ctx,
					 struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials verify callback.
 *
 * \param[in] user_ctx          User context.
 * \param[in,out] auth_cred     Peer credentials types defined by COSE IANA registry.
 * \param[out] pub_key          Pointer address where the public key address is to be written.
 * \param[out] pub_key_len      On success, the number of bytes that make up the public key.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_credentials_verify_t)(void *user_ctx,
					  struct edhoc_auth_creds *auth_cred,
					  const uint8_t **pub_key,
					  size_t *pub_key_len);

/**
 * \brief Structure for EDHOC authentication credentials.
 */
struct edhoc_credentials {
	edhoc_credentials_fetch_t fetch;
	edhoc_credentials_verify_t verify;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_CREDENTIALS_H */