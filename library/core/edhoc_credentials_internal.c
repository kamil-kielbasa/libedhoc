/**
 * \file    edhoc_credentials_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC authentication credentials:
 *          - ID_CRED_x decoding.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_macros_internal.h"
#include "edhoc_credentials_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_x509_types.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Decode the 'x5chain' header parameter (RFC 9360: 2).
 *
 * \param[in] cose_x509                 Decoded COSE_X509.
 * \param[out] credentials              On success, authentication credentials.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int parse_x5chain(const struct COSE_X509_r *cose_x509,
			 struct edhoc_auth_credentials *credentials);

/**
 * \brief Decode the 'x5t' header parameter (RFC 9360: 2).
 *
 * \param[in] cert_hash                 Decoded COSE_CertHash.
 * \param[out] credentials              On success, authentication credentials.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int parse_x5t(const struct COSE_CertHash *cert_hash,
		     struct edhoc_auth_credentials *credentials);

/* Static function definitions --------------------------------------------- */

STATIC int parse_x5chain(const struct COSE_X509_r *cose_x509,
			 struct edhoc_auth_credentials *credentials)
{
	/* One slot is reserved so the array stays valid for a chain length of
	 * zero, see the declaration of struct edhoc_auth_credential_x509_chain. */
	const size_t capacity =
		ARRAY_SIZE(credentials->x509_chain.certificate) - 1;

	switch (cose_x509->COSE_X509_choice) {
	case COSE_X509_bstr_c:
		credentials->label = EDHOC_COSE_HEADER_X509_CHAIN;
		credentials->x509_chain.certificate_count = 1;
		credentials->x509_chain.certificate[0] =
			cose_x509->COSE_X509_bstr.value;
		credentials->x509_chain.certificate_length[0] =
			cose_x509->COSE_X509_bstr.len;
		break;

	case COSE_X509_certs_l_c:
		if (capacity < cose_x509->COSE_X509_certs_l_certs_count) {
			EDHOC_LOG_ERR(
				"X.509 certificate chain too large: %zu (max %zu)",
				cose_x509->COSE_X509_certs_l_certs_count,
				capacity);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		credentials->label = EDHOC_COSE_HEADER_X509_CHAIN;
		credentials->x509_chain.certificate_count =
			cose_x509->COSE_X509_certs_l_certs_count;

		for (size_t i = 0; i < cose_x509->COSE_X509_certs_l_certs_count;
		     ++i) {
			credentials->x509_chain.certificate[i] =
				cose_x509->COSE_X509_certs_l_certs[i].value;
			credentials->x509_chain.certificate_length[i] =
				cose_x509->COSE_X509_certs_l_certs[i].len;
		}
		break;

	default:
		EDHOC_LOG_ERR("Invalid COSE_X509 choice: %d",
			      cose_x509->COSE_X509_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_x5t(const struct COSE_CertHash *cert_hash,
		     struct edhoc_auth_credentials *credentials)
{
	if (EDHOC_X509_HASH_FINGERPRINT_MAX_LEN <
	    cert_hash->COSE_CertHash_hashValue.len) {
		EDHOC_LOG_ERR(
			"X.509 certificate fingerprint too large: %zu (max %d)",
			cert_hash->COSE_CertHash_hashValue.len,
			EDHOC_X509_HASH_FINGERPRINT_MAX_LEN);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	switch (cert_hash->COSE_CertHash_hashAlg_choice) {
	case COSE_CertHash_hashAlg_int_c:
		credentials->x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
		credentials->x509_hash.algorithm_int =
			cert_hash->COSE_CertHash_hashAlg_int;
		break;

	case COSE_CertHash_hashAlg_tstr_c:
		if (ARRAY_SIZE(credentials->x509_hash.algorithm_bstr.value) <
		    cert_hash->COSE_CertHash_hashAlg_tstr.len) {
			EDHOC_LOG_ERR(
				"X.509 hash algorithm string too large: %zu",
				cert_hash->COSE_CertHash_hashAlg_tstr.len);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		credentials->x509_hash.encode_type =
			EDHOC_ENCODE_TYPE_BYTE_STRING;
		credentials->x509_hash.algorithm_bstr.length =
			cert_hash->COSE_CertHash_hashAlg_tstr.len;
		memcpy(credentials->x509_hash.algorithm_bstr.value,
		       cert_hash->COSE_CertHash_hashAlg_tstr.value,
		       cert_hash->COSE_CertHash_hashAlg_tstr.len);
		break;

	default:
		EDHOC_LOG_ERR("Invalid COSE_CertHash_hashAlg choice: %d",
			      cert_hash->COSE_CertHash_hashAlg_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	credentials->label = EDHOC_COSE_HEADER_X509_HASH;
	credentials->x509_hash.certificate_fingerprint =
		cert_hash->COSE_CertHash_hashValue.value;
	credentials->x509_hash.certificate_fingerprint_length =
		cert_hash->COSE_CertHash_hashValue.len;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_parse_id_cred_kid_int(int32_t key_id,
				struct edhoc_auth_credentials *credentials)
{
	if (NULL == credentials) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	credentials->label = EDHOC_COSE_HEADER_KID;
	credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	credentials->key_id.key_id_int = key_id;

	return EDHOC_SUCCESS;
}

int edhoc_parse_id_cred_kid_bstr(const uint8_t *key_id, size_t key_id_length,
				 struct edhoc_auth_credentials *credentials)
{
	if (NULL == key_id || NULL == credentials) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* One slot is reserved so the array stays valid for a key identifier
	 * length of zero, see struct edhoc_auth_credential_key_id. */
	const size_t capacity =
		ARRAY_SIZE(credentials->key_id.key_id_bstr.value) - 1;

	if (capacity < key_id_length) {
		EDHOC_LOG_ERR("Key identifier too large: %zu (max %zu)",
			      key_id_length, capacity);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	credentials->label = EDHOC_COSE_HEADER_KID;
	credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	credentials->key_id.key_id_bstr.length = key_id_length;
	memcpy(credentials->key_id.key_id_bstr.value, key_id, key_id_length);

	return EDHOC_SUCCESS;
}

int edhoc_parse_id_cred_map(const struct map *id_cred_map,
			    struct edhoc_auth_credentials *credentials)
{
	if (NULL == id_cred_map || NULL == credentials) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* RFC 9528: 3.5.3.2 - "These optimizations MUST be applied if and only
	 * if ID_CRED_x = { 4 : kid_x }". A lone 'kid' therefore always travels
	 * as a bare integer or byte string, never as a map. Reaching this branch
	 * means either that the peer ignored the mandatory compact encoding, or
	 * that the map carries 'kid' alongside header parameters this library
	 * does not support. In both cases the credential cannot be resolved. */
	if (id_cred_map->map_kid_present) {
		EDHOC_LOG_ERR("ID_CRED 'kid' must use the compact encoding");
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (id_cred_map->map_x5chain_present && id_cred_map->map_x5t_present) {
		EDHOC_LOG_ERR("Ambiguous ID_CRED: 'x5chain' and 'x5t'");
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (id_cred_map->map_x5chain_present) {
		return parse_x5chain(&id_cred_map->map_x5chain.map_x5chain,
				     credentials);
	}

	if (id_cred_map->map_x5t_present) {
		return parse_x5t(&id_cred_map->map_x5t.map_x5t, credentials);
	}

	/* Header parameters outside the CDDL model are rejected earlier, by the
	 * CBOR decoder, so an empty map is the only way to get here. */
	EDHOC_LOG_ERR("No supported ID_CRED header parameter");
	return EDHOC_ERROR_NOT_PERMITTED;
}
