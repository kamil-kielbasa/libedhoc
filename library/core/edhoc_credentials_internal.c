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
#include "edhoc_common_internal.h"
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
#include <backend_cbor_id_cred_x_encode.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_bstr_type_encode.h>

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
 * \brief Compute the number of bytes an integer or byte string occupies once
 *        CBOR encoded.
 *
 * \param[in] value                     Integer or byte string.
 *
 * \return Number of bytes.
 */
STATIC size_t
cbor_int_or_string_len(const struct edhoc_cbor_int_or_string *value);

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
 * \brief Validate the serialization of a credential against its label.
 *
 * \param label                        Identification method.
 * \param format                       Credential format.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int validate_format(enum edhoc_cose_header label,
			   enum edhoc_credential_format format);

/**
 * \brief Decode the 'x5chain' header parameter (RFC 9360: 2).
 *
 * \param[in] cose_x509                 Decoded COSE_X509.
 * \param[out] received                 On success, peer identification.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int parse_x5chain(const struct COSE_X509_r *cose_x509,
			 struct edhoc_credential_received *received);

/**
 * \brief Decode the 'x5t' header parameter (RFC 9360: 2).
 *
 * \param[in] cert_hash                 Decoded COSE_CertHash.
 * \param[out] received                 On success, peer identification.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int parse_x5t(const struct COSE_CertHash *cert_hash,
		     struct edhoc_credential_received *received);

/**
 * \brief Check whether a byte is a complete CBOR integer on its own.
 *
 * \param value                         Candidate byte.
 *
 * \return True for CBOR major type 0 or 1 with the argument in the initial
 *         byte, otherwise false.
 */
STATIC bool is_one_byte_cbor_int(uint8_t value);

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
 * \brief Copy a CBOR item the application delivered ready to embed.
 *
 * \param[in] item                      Encoded item.
 * \param[out] buffer                   On success, the copied item.
 * \param buffer_length                 Size of \p buffer in bytes.
 * \param[out] length                   On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
STATIC int copy_encoded_item(const struct edhoc_buffer *item, uint8_t *buffer,
			     size_t buffer_length, size_t *length);

/* Static function definitions --------------------------------------------- */

STATIC size_t
cbor_int_or_string_len(const struct edhoc_cbor_int_or_string *value)
{
	if (NULL == value) {
		EDHOC_LOG_ERR("Invalid argument");
		return 0;
	}

	switch (value->encode_type) {
	case EDHOC_ENCODE_TYPE_INTEGER:
		return edhoc_cbor_int_mem_req(value->integer);
	case EDHOC_ENCODE_TYPE_STRING:
		return value->string.length +
		       edhoc_cbor_bstr_oh(value->string.length);
	}

	return 0;
}

STATIC bool is_buffer_empty(const uint8_t *buffer, size_t length)
{
	return NULL == buffer || 0 == length;
}

STATIC bool is_one_byte_cbor_int(uint8_t value)
{
	const uint8_t cbor_unsigned_max = 0x17u;
	const uint8_t cbor_negative_min = 0x20u;
	const uint8_t cbor_negative_max = 0x37u;

	return value <= cbor_unsigned_max ||
	       (cbor_negative_min <= value && value <= cbor_negative_max);
}

STATIC int validate_format(enum edhoc_cose_header label,
			   enum edhoc_credential_format format)
{
	switch (label) {
	case EDHOC_COSE_HEADER_KID:
		/* CRED may be a CBOR item (a CWT or a CCS) or opaque bytes. */
		if (EDHOC_CREDENTIAL_FORMAT_RAW != format &&
		    EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED != format) {
			EDHOC_LOG_ERR("Invalid format for 'kid': %d", format);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
	case EDHOC_COSE_HEADER_X509_HASH:
		/* CRED is the DER certificate, never a CBOR item. */
		if (EDHOC_CREDENTIAL_FORMAT_RAW != format) {
			EDHOC_LOG_ERR("Invalid format for X.509: %d", format);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d", label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_x5chain(const struct COSE_X509_r *cose_x509,
			 struct edhoc_credential_received *received)
{
	if (NULL == cose_x509 || NULL == received) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	switch (cose_x509->COSE_X509_choice) {
	case COSE_X509_bstr_c:
		received->label = EDHOC_COSE_HEADER_X509_CHAIN;
		received->x509_chain.count = 1;
		received->x509_chain.certificate[0].value =
			cose_x509->COSE_X509_bstr.value;
		received->x509_chain.certificate[0].length =
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

		received->label = EDHOC_COSE_HEADER_X509_CHAIN;
		received->x509_chain.count =
			cose_x509->COSE_X509_certs_l_certs_count;

		for (size_t i = 0; i < cose_x509->COSE_X509_certs_l_certs_count;
		     ++i) {
			received->x509_chain.certificate[i].value =
				cose_x509->COSE_X509_certs_l_certs[i].value;
			received->x509_chain.certificate[i].length =
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
		     struct edhoc_credential_received *received)
{
	if (NULL == cert_hash || NULL == received) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

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
		received->x509_hash.algorithm.encode_type =
			EDHOC_ENCODE_TYPE_INTEGER;
		received->x509_hash.algorithm.integer =
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

		received->x509_hash.algorithm.encode_type =
			EDHOC_ENCODE_TYPE_STRING;
		received->x509_hash.algorithm.string.value =
			cert_hash->COSE_CertHash_hashAlg_tstr.value;
		received->x509_hash.algorithm.string.length =
			cert_hash->COSE_CertHash_hashAlg_tstr.len;
		break;

	default:
		EDHOC_LOG_ERR("Invalid COSE_CertHash_hashAlg choice: %d",
			      cert_hash->COSE_CertHash_hashAlg_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	received->label = EDHOC_COSE_HEADER_X509_HASH;
	received->x509_hash.fingerprint.value =
		cert_hash->COSE_CertHash_hashValue.value;
	received->x509_hash.fingerprint.length =
		cert_hash->COSE_CertHash_hashValue.len;

	return EDHOC_SUCCESS;
}

STATIC int validate_key_id(const struct edhoc_auth_credential_key_id *key_id)
{
	if (NULL == key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

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
	if (NULL == chain) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

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
	if (NULL == x509_hash) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

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

STATIC int copy_encoded_item(const struct edhoc_buffer *item, uint8_t *buffer,
			     size_t buffer_length, size_t *length)
{
	if (NULL == item || NULL == buffer || 0 == buffer_length ||
	    NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (buffer_length < item->length) {
		EDHOC_LOG_ERR("Buffer too small: %zu > %zu", item->length,
			      buffer_length);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(buffer, item->value, item->length);
	*length = item->length;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_credential_parse_kid_int(int32_t key_id, uint8_t *key_id_byte,
				   struct edhoc_credential_received *received)
{
	if (NULL == key_id_byte || NULL == received) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* RFC 9528: 3.3.2 - the integer is the transport encoding of the byte
	 * string that its own CBOR encoding consists of, which only holds when
	 * that encoding is a single byte. Re-encoding recovers the byte and
	 * rejects any wider integer in one step. */
	size_t encoded_length = 0;
	const int ret = cbor_encode_integer_type_int_type(
		key_id_byte, sizeof(*key_id_byte), &key_id, &encoded_length);

	if (ZCBOR_SUCCESS != ret || sizeof(*key_id_byte) != encoded_length) {
		EDHOC_LOG_ERR("Key identifier int is not one byte: %d",
			      (int)key_id);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	received->label = EDHOC_COSE_HEADER_KID;
	received->kid.identifier.value = key_id_byte;
	received->kid.identifier.length = sizeof(*key_id_byte);

	return EDHOC_SUCCESS;
}

int edhoc_credential_parse_kid_bstr(const uint8_t *key_id, size_t key_id_length,
				    struct edhoc_credential_received *received)
{
	if (NULL == key_id || NULL == received) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CREDENTIAL_KID_MAX_LEN < key_id_length) {
		EDHOC_LOG_ERR("Key identifier too large: %zu (max %d)",
			      key_id_length, EDHOC_CREDENTIAL_KID_MAX_LEN);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	received->label = EDHOC_COSE_HEADER_KID;
	received->kid.identifier.value = key_id;
	received->kid.identifier.length = key_id_length;

	return EDHOC_SUCCESS;
}

int edhoc_credential_parse_map(const struct map *id_cred_map,
			       struct edhoc_credential_received *received)
{
	if (NULL == id_cred_map || NULL == received) {
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
				     received);
	}

	if (id_cred_map->map_x5t_present) {
		return parse_x5t(&id_cred_map->map_x5t.map_x5t, received);
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

	int ret = validate_format(credentials->label, credentials->format);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

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

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      credentials->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return ret;
}

int edhoc_credential_validate_trusted(
	const struct edhoc_credential_received *received,
	const struct edhoc_credential_trusted *trusted)
{
	if (NULL == received || NULL == trusted) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const bool no_credential = is_buffer_empty(trusted->credential.value,
						 trusted->credential.length);

	if (no_credential) {
		EDHOC_LOG_ERR("Empty peer credential");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	const bool no_public_key = is_buffer_empty(trusted->public_key.value,
						   trusted->public_key.length);

	if (no_public_key) {
		EDHOC_LOG_ERR("Empty peer authentication key");
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	switch (received->label) {
	case EDHOC_COSE_HEADER_KID:
		/* CRED may be a CBOR item (a CWT or a CCS) or opaque bytes. */
		if (EDHOC_CREDENTIAL_FORMAT_RAW != trusted->format &&
		    EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED != trusted->format) {
			EDHOC_LOG_ERR("Invalid format for 'kid': %d",
				      trusted->format);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
	case EDHOC_COSE_HEADER_X509_HASH:
		/* CRED is the DER certificate, never a CBOR item. */
		if (EDHOC_CREDENTIAL_FORMAT_RAW != trusted->format) {
			EDHOC_LOG_ERR("Invalid format for X.509: %d",
				      trusted->format);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      received->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_SUCCESS;
}

int edhoc_credential_material_from_trusted(
	const struct edhoc_credential_received *received,
	const struct edhoc_credential_trusted *trusted,
	struct edhoc_credential_material *material)
{
	if (NULL == received || NULL == trusted || NULL == material) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	memset(material, 0, sizeof(*material));

	material->label = received->label;
	material->format = trusted->format;
	material->credential = trusted->credential;

	switch (received->label) {
	case EDHOC_COSE_HEADER_KID:
		material->kid.encode_type = EDHOC_ENCODE_TYPE_STRING;
		material->kid.string = received->kid.identifier;
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t count = received->x509_chain.count;

		if (0 == count || EDHOC_CREDENTIAL_X5CHAIN_CAPACITY < count) {
			EDHOC_LOG_ERR("Invalid X.509 chain length: %zu", count);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		material->x509_chain.count = count;
		for (size_t i = 0; i < count; ++i) {
			material->x509_chain.certificate[i] =
				received->x509_chain.certificate[i];
		}

		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH:
		material->x509_hash.algorithm = received->x509_hash.algorithm;
		material->x509_hash.fingerprint =
			received->x509_hash.fingerprint;
		break;

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      received->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_SUCCESS;
}

int edhoc_credential_material_from_auth(
	const struct edhoc_auth_credentials *credentials,
	struct edhoc_credential_material *material)
{
	if (NULL == credentials || NULL == material) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	memset(material, 0, sizeof(*material));

	material->label = credentials->label;
	material->format = credentials->format;

	switch (credentials->label) {
	case EDHOC_COSE_HEADER_KID:
		material->credential.value = credentials->key_id.credential;
		material->credential.length =
			credentials->key_id.credential_length;

		material->kid.encode_type = credentials->key_id.encode_type;

		switch (credentials->key_id.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			material->kid.integer = credentials->key_id.key_id_int;
			break;
		case EDHOC_ENCODE_TYPE_STRING:
			material->kid.string.value =
				credentials->key_id.key_id_bstr.value;
			material->kid.string.length =
				credentials->key_id.key_id_bstr.length;
			break;
		default:
			EDHOC_LOG_ERR("Invalid key identifier encode type: %d",
				      credentials->key_id.encode_type);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t count = credentials->x509_chain.certificate_count;

		if (0 == count || EDHOC_CREDENTIAL_X5CHAIN_CAPACITY < count) {
			EDHOC_LOG_ERR("Invalid X.509 chain length: %zu", count);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		material->x509_chain.count = count;
		for (size_t i = 0; i < count; ++i) {
			material->x509_chain.certificate[i].value =
				credentials->x509_chain.certificate[i];
			material->x509_chain.certificate[i].length =
				credentials->x509_chain.certificate_length[i];
		}

		/* CRED is the end-entity certificate. */
		material->credential = material->x509_chain.certificate[0];
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH:
		material->credential.value = credentials->x509_hash.certificate;
		material->credential.length =
			credentials->x509_hash.certificate_length;

		material->x509_hash.fingerprint.value =
			credentials->x509_hash.certificate_fingerprint;
		material->x509_hash.fingerprint.length =
			credentials->x509_hash.certificate_fingerprint_length;

		material->x509_hash.algorithm.encode_type =
			credentials->x509_hash.encode_type;

		switch (credentials->x509_hash.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			material->x509_hash.algorithm.integer =
				credentials->x509_hash.algorithm_int;
			break;
		case EDHOC_ENCODE_TYPE_STRING:
			material->x509_hash.algorithm.string.value =
				credentials->x509_hash.algorithm_bstr.value;
			material->x509_hash.algorithm.string.length =
				credentials->x509_hash.algorithm_bstr.length;
			break;
		default:
			EDHOC_LOG_ERR("Invalid hash algorithm encode type: %d",
				      credentials->x509_hash.encode_type);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      credentials->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_SUCCESS;
}

int edhoc_credential_id_cred_length(
	const struct edhoc_credential_material *material, size_t *length)
{
	if (NULL == material || NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const size_t nr_of_items = 1;

	*length = edhoc_cbor_map_oh(nr_of_items);

	switch (material->label) {
	case EDHOC_COSE_HEADER_KID:
		*length += cbor_int_or_string_len(&material->kid);
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		for (size_t i = 0; i < material->x509_chain.count; ++i) {
			const size_t len =
				material->x509_chain.certificate[i].length;

			*length += len + edhoc_cbor_bstr_oh(len);
		}

		if (1 < material->x509_chain.count) {
			*length +=
				edhoc_cbor_array_oh(material->x509_chain.count);
		}

		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		*length += edhoc_cbor_array_oh(nr_of_items);
		*length +=
			cbor_int_or_string_len(&material->x509_hash.algorithm);
		*length += material->x509_hash.fingerprint.length;
		*length += edhoc_cbor_bstr_oh(
			material->x509_hash.fingerprint.length);
		break;

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      material->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_SUCCESS;
}

int edhoc_credential_cred_length(
	const struct edhoc_credential_material *material, size_t *length)
{
	if (NULL == material || NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	switch (material->label) {
	case EDHOC_COSE_HEADER_KID:
	case EDHOC_COSE_HEADER_X509_CHAIN:
	case EDHOC_COSE_HEADER_X509_HASH:
		break;

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      material->label);
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	*length = material->credential.length +
		  edhoc_cbor_bstr_oh(material->credential.length);

	return EDHOC_SUCCESS;
}

int edhoc_credential_encode_id_cred(
	const struct edhoc_credential_material *material, uint8_t *buffer,
	size_t buffer_length, size_t *length)
{
	if (NULL == material || NULL == buffer || 0 == buffer_length ||
	    NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	struct id_cred_x id_cred = { 0 };

	switch (material->label) {
	case EDHOC_COSE_HEADER_KID: {
		id_cred.id_cred_x_kid_present = true;

		struct id_cred_x_kid_r *kid = &id_cred.id_cred_x_kid;

		switch (material->kid.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			kid->id_cred_x_kid_choice = id_cred_x_kid_int_c;
			kid->id_cred_x_kid_int = material->kid.integer;
			break;
		case EDHOC_ENCODE_TYPE_STRING:
			kid->id_cred_x_kid_choice = id_cred_x_kid_bstr_c;
			kid->id_cred_x_kid_bstr.value =
				material->kid.string.value;
			kid->id_cred_x_kid_bstr.len =
				material->kid.string.length;
			break;
		default:
			EDHOC_LOG_ERR("Invalid key identifier encode type: %d",
				      material->kid.encode_type);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;
	}

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t count = material->x509_chain.count;

		if (0 == count || EDHOC_CREDENTIAL_X5CHAIN_CAPACITY < count) {
			EDHOC_LOG_ERR("Invalid X.509 chain length: %zu", count);
			return EDHOC_ERROR_BAD_STATE;
		}

		id_cred.id_cred_x_x5chain_present = true;

		struct COSE_X509_r *x5chain =
			&id_cred.id_cred_x_x5chain.id_cred_x_x5chain;

		if (1 == count) {
			x5chain->COSE_X509_choice = COSE_X509_bstr_c;
			x5chain->COSE_X509_bstr.value =
				material->x509_chain.certificate[0].value;
			x5chain->COSE_X509_bstr.len =
				material->x509_chain.certificate[0].length;
			break;
		}

		x5chain->COSE_X509_choice = COSE_X509_certs_l_c;
		x5chain->COSE_X509_certs_l_certs_count = count;

		for (size_t i = 0; i < count; ++i) {
			x5chain->COSE_X509_certs_l_certs[i].value =
				material->x509_chain.certificate[i].value;
			x5chain->COSE_X509_certs_l_certs[i].len =
				material->x509_chain.certificate[i].length;
		}
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH: {
		id_cred.id_cred_x_x5t_present = true;

		struct COSE_CertHash *x5t =
			&id_cred.id_cred_x_x5t.id_cred_x_x5t;

		x5t->COSE_CertHash_hashValue.value =
			material->x509_hash.fingerprint.value;
		x5t->COSE_CertHash_hashValue.len =
			material->x509_hash.fingerprint.length;

		switch (material->x509_hash.algorithm.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			x5t->COSE_CertHash_hashAlg_choice =
				COSE_CertHash_hashAlg_int_c;
			x5t->COSE_CertHash_hashAlg_int =
				material->x509_hash.algorithm.integer;
			break;
		case EDHOC_ENCODE_TYPE_STRING:
			x5t->COSE_CertHash_hashAlg_choice =
				COSE_CertHash_hashAlg_tstr_c;
			x5t->COSE_CertHash_hashAlg_tstr.value =
				material->x509_hash.algorithm.string.value;
			x5t->COSE_CertHash_hashAlg_tstr.len =
				material->x509_hash.algorithm.string.length;
			break;
		default:
			EDHOC_LOG_ERR(
				"Invalid hash algorithm encode type: %d",
				material->x509_hash.algorithm.encode_type);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;
	}

	case EDHOC_COSE_HEADER_NONE:
	default:
		EDHOC_LOG_ERR("Unsupported credential label: %d",
			      material->label);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	const int ret =
		cbor_encode_id_cred_x(buffer, buffer_length, &id_cred, length);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc ID_CRED: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_credential_encode_id_cred_compact(
	const struct edhoc_credential_material *material, uint8_t *buffer,
	size_t buffer_length, size_t *length)
{
	if (NULL == material || NULL == buffer || 0 == buffer_length ||
	    NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	*length = 0;

	if (EDHOC_COSE_HEADER_KID != material->label) {
		return EDHOC_SUCCESS;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (material->kid.encode_type) {
	case EDHOC_ENCODE_TYPE_INTEGER:
		ret = cbor_encode_integer_type_int_type(
			buffer, buffer_length, &material->kid.integer, length);
		break;

	case EDHOC_ENCODE_TYPE_STRING: {
		/* RFC 9528: 3.3.2 - a byte string identifier that is one byte
		 * long and whose byte is a complete CBOR integer travels as
		 * that integer. Everything else is a plain byte string. */
		if (1 == material->kid.string.length &&
		    is_one_byte_cbor_int(material->kid.string.value[0])) {
			buffer[0] = material->kid.string.value[0];
			*length = 1;

			return EDHOC_SUCCESS;
		}

		const struct zcbor_string input = {
			.value = material->kid.string.value,
			.len = material->kid.string.length,
		};

		ret = cbor_encode_byte_string_type_bstr_type(
			buffer, buffer_length, &input, length);
		break;
	}

	default:
		EDHOC_LOG_ERR("Invalid key identifier encode type: %d",
			      material->kid.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc key identifier: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_credential_encode_cred(
	const struct edhoc_credential_material *material, uint8_t *buffer,
	size_t buffer_length, size_t *length)
{
	if (NULL == material || NULL == buffer || 0 == buffer_length ||
	    NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	switch (material->format) {
	case EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED:
		return copy_encoded_item(&material->credential, buffer,
					 buffer_length, length);

	case EDHOC_CREDENTIAL_FORMAT_RAW: {
		const struct zcbor_string cred = {
			.value = material->credential.value,
			.len = material->credential.length,
		};

		const int ret = cbor_encode_byte_string_type_bstr_type(
			buffer, buffer_length, &cred, length);

		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("CBOR enc CRED: %d", ret);
			return EDHOC_ERROR_CBOR_FAILURE;
		}

		return EDHOC_SUCCESS;
	}

	case EDHOC_CREDENTIAL_FORMAT_NONE:
	default:
		EDHOC_LOG_ERR("Invalid credential format: %d",
			      material->format);
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}
