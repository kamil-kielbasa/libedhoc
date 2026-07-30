/**
 * \file    edhoc_credentials_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC authentication credentials:
 *          - ID_CRED_x decoding.
 *          - validation of what the application returns.
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
#include <stdbool.h>
#include <string.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_x509_types.h>

/* Module defines ---------------------------------------------------------- */

/* The chain capacity must fit the generated CBOR model, which caps the array
 * form of COSE_X509 at its own compile-time size. */
_Static_assert(
	EDHOC_CREDENTIAL_X5CHAIN_CAPACITY <=
		ARRAY_SIZE(((struct COSE_X509_r *)0)->COSE_X509_certs_l_certs),
	"X.509 chain capacity exceeds the CBOR backend model");

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Check whether a buffer reference is unusable.
 *
 * \param[in] buffer                    Buffer reference.
 * \param length                        Length of \p buffer in bytes.
 *
 * \return True if the reference is missing or empty, otherwise false.
 */
STATIC bool is_buffer_empty(const uint8_t *buffer, size_t length);

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

/**
 * \brief Validate a credential referenced by a key identifier.
 *
 * \param[in] key_id                    Key identifier credential.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int validate_key_id(const struct edhoc_auth_credential_key_id *key_id);

/**
 * \brief Validate an X.509 certificate chain supplied by the application.
 *
 * \param[in] chain                     Certificate chain.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int
validate_x509_chain(const struct edhoc_auth_credential_x509_chain *chain);

/**
 * \brief Validate a credential referenced by a certificate fingerprint.
 *
 * \param[in] x509_hash                 Certificate fingerprint credential.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int
validate_x509_hash(const struct edhoc_auth_credential_x509_hash *x509_hash);

/**
 * \brief Validate a credential the application encodes itself.
 *
 * \param[in] custom                    Custom credential.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int validate_custom(const struct edhoc_auth_credential_custom *custom);

/* Static function definitions --------------------------------------------- */

STATIC bool is_buffer_empty(const uint8_t *buffer, size_t length)
{
	return NULL == buffer || 0 == length;
}

STATIC int parse_x5chain(const struct COSE_X509_r *cose_x509,
			 struct edhoc_auth_credentials *credentials)
{
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
		if (EDHOC_CREDENTIAL_X5CHAIN_CAPACITY <
		    cose_x509->COSE_X509_certs_l_certs_count) {
			EDHOC_LOG_ERR(
				"X.509 certificate chain too large: %zu (max %d)",
				cose_x509->COSE_X509_certs_l_certs_count,
				EDHOC_CREDENTIAL_X5CHAIN_CAPACITY);
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
	if (EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN <
	    cert_hash->COSE_CertHash_hashValue.len) {
		EDHOC_LOG_ERR(
			"X.509 certificate fingerprint too large: %zu (max %d)",
			cert_hash->COSE_CertHash_hashValue.len,
			EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	switch (cert_hash->COSE_CertHash_hashAlg_choice) {
	case COSE_CertHash_hashAlg_int_c:
		credentials->x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
		credentials->x509_hash.algorithm_int =
			cert_hash->COSE_CertHash_hashAlg_int;
		break;

	case COSE_CertHash_hashAlg_tstr_c:
		if (EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN <
		    cert_hash->COSE_CertHash_hashAlg_tstr.len) {
			EDHOC_LOG_ERR(
				"X.509 hash algorithm string too large: %zu (max %d)",
				cert_hash->COSE_CertHash_hashAlg_tstr.len,
				EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		credentials->x509_hash.encode_type = EDHOC_ENCODE_TYPE_STRING;
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

STATIC int validate_key_id(const struct edhoc_auth_credential_key_id *key_id)
{
	const bool no_credential =
		is_buffer_empty(key_id->credential, key_id->credential_length);

	if (no_credential) {
		EDHOC_LOG_ERR("Empty credential for 'kid'");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	switch (key_id->encode_type) {
	case EDHOC_ENCODE_TYPE_INTEGER:
		break;

	case EDHOC_ENCODE_TYPE_STRING:
		if (EDHOC_CREDENTIAL_KID_MAX_LEN < key_id->key_id_bstr.length) {
			EDHOC_LOG_ERR("Key identifier too large: %zu (max %d)",
				      key_id->key_id_bstr.length,
				      EDHOC_CREDENTIAL_KID_MAX_LEN);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}
		break;

	default:
		EDHOC_LOG_ERR("Invalid key identifier encode type: %d",
			      key_id->encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

STATIC int
validate_x509_chain(const struct edhoc_auth_credential_x509_chain *chain)
{
	if (0 == chain->certificate_count ||
	    EDHOC_CREDENTIAL_X5CHAIN_CAPACITY < chain->certificate_count) {
		EDHOC_LOG_ERR("Invalid X.509 chain length: %zu",
			      chain->certificate_count);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	for (size_t i = 0; i < chain->certificate_count; ++i) {
		const bool no_certificate = is_buffer_empty(
			chain->certificate[i], chain->certificate_length[i]);

		if (no_certificate) {
			EDHOC_LOG_ERR("Empty X.509 certificate at index: %zu",
				      i);
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}
	}

	return EDHOC_SUCCESS;
}

STATIC int
validate_x509_hash(const struct edhoc_auth_credential_x509_hash *x509_hash)
{
	const bool no_certificate = is_buffer_empty(
		x509_hash->certificate, x509_hash->certificate_length);

	if (no_certificate) {
		EDHOC_LOG_ERR("Empty certificate for 'x5t'");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	const bool no_fingerprint =
		is_buffer_empty(x509_hash->certificate_fingerprint,
				x509_hash->certificate_fingerprint_length);

	if (no_fingerprint) {
		EDHOC_LOG_ERR("Empty certificate fingerprint");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN <
	    x509_hash->certificate_fingerprint_length) {
		EDHOC_LOG_ERR("Certificate fingerprint too large: %zu (max %d)",
			      x509_hash->certificate_fingerprint_length,
			      EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	switch (x509_hash->encode_type) {
	case EDHOC_ENCODE_TYPE_INTEGER:
		break;

	case EDHOC_ENCODE_TYPE_STRING:
		if (EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN <
		    x509_hash->algorithm_bstr.length) {
			EDHOC_LOG_ERR(
				"Hash algorithm string too large: %zu (max %d)",
				x509_hash->algorithm_bstr.length,
				EDHOC_CREDENTIAL_X5T_ALGORITHM_MAX_LEN);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}
		break;

	default:
		EDHOC_LOG_ERR("Invalid hash algorithm encode type: %d",
			      x509_hash->encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

STATIC int validate_custom(const struct edhoc_auth_credential_custom *custom)
{
	const bool no_id_credential = is_buffer_empty(
		custom->id_credential, custom->id_credential_length);
	const bool no_credential =
		is_buffer_empty(custom->credential, custom->credential_length);

	if (no_id_credential || no_credential) {
		EDHOC_LOG_ERR("Empty custom credential");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	const bool no_compact =
		is_buffer_empty(custom->id_credential_compact,
				custom->id_credential_compact_length);

	if (custom->is_id_credential_compact_encoded && no_compact) {
		EDHOC_LOG_ERR("Empty compact ID_CRED for custom credential");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

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

	if (EDHOC_CREDENTIAL_KID_MAX_LEN < key_id_length) {
		EDHOC_LOG_ERR("Key identifier too large: %zu (max %d)",
			      key_id_length, EDHOC_CREDENTIAL_KID_MAX_LEN);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	credentials->label = EDHOC_COSE_HEADER_KID;
	credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_STRING;
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

int edhoc_validate_credential_fetched(
	const struct edhoc_auth_credentials *credentials)
{
	if (NULL == credentials) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (credentials->label) {
	case EDHOC_COSE_HEADER_KID:
		ret = validate_key_id(&credentials->key_id);
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		ret = validate_x509_chain(&credentials->x509_chain);
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		ret = validate_x509_hash(&credentials->x509_hash);
		break;

	case EDHOC_COSE_HEADER_CUSTOM:
		ret = validate_custom(&credentials->custom);
		break;

	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      credentials->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return ret;
}

int edhoc_validate_credential_verified(
	const struct edhoc_auth_credentials *credentials,
	const uint8_t *public_key, size_t public_key_length)
{
	if (NULL == credentials) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const bool no_public_key =
		is_buffer_empty(public_key, public_key_length);

	if (no_public_key) {
		EDHOC_LOG_ERR("Empty peer authentication key");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* The identification half of ID_CRED_x comes from the decoder and was
	 * validated there, so only CRED_x, which the application resolves, is
	 * checked here. */
	switch (credentials->label) {
	case EDHOC_COSE_HEADER_KID: {
		const bool no_credential =
			is_buffer_empty(credentials->key_id.credential,
					credentials->key_id.credential_length);

		if (no_credential) {
			EDHOC_LOG_ERR("Empty credential for 'kid'");
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}
		break;
	}

	case EDHOC_COSE_HEADER_X509_CHAIN:
		return validate_x509_chain(&credentials->x509_chain);

	case EDHOC_COSE_HEADER_X509_HASH: {
		const bool no_certificate = is_buffer_empty(
			credentials->x509_hash.certificate,
			credentials->x509_hash.certificate_length);

		if (no_certificate) {
			EDHOC_LOG_ERR("Empty certificate for 'x5t'");
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}
		break;
	}

	/* ID_CRED_x has no wire form the decoder maps to a custom credential,
	 * so this label can only come from the application overwriting it. */
	case EDHOC_COSE_HEADER_CUSTOM:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      credentials->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_SUCCESS;
}
