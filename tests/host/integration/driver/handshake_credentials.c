/**
 * \file    handshake_credentials.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the generic handshake-driver credential callbacks.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Handshake driver headers: */
#include "handshake_credentials.h"
#include "handshake_driver.h"

/* EDHOC public headers: */
#include <edhoc/edhoc.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <string.h>

/* Module defines ---------------------------------------------------------- */

/** \brief COSE algorithm identifier SHA-256/64 (truncated SHA-256). */
#define HS_COSE_ALG_SHA_256_64 (-15)

/** \brief Largest certificate-thumbprint hash this module computes. */
#define HS_THUMBPRINT_HASH_MAX ((size_t)32)

#if defined(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE) && \
	CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE
extern int edhoc_cipher_suite_pqc_1_import_signing_key(
	const uint8_t *signing_key, size_t signing_key_length, void *key_id);
#endif

/* Static function declarations -------------------------------------------- */

/**
 * \brief Import a private authentication key and store its handle in \p key_id.
 */
static int hs_import_private_key(enum hs_key_import key_import,
				 const uint8_t *private_key,
				 size_t private_key_length, void *key_id);

/**
 * \brief Compute the certificate thumbprint for \p cose_algorithm.
 */
static int hs_thumbprint_hash(int32_t cose_algorithm, const uint8_t *data,
			      size_t data_length, uint8_t *hash,
			      size_t hash_size, size_t *hash_length);

/* Static function definitions --------------------------------------------- */

static int hs_import_private_key(enum hs_key_import key_import,
				 const uint8_t *private_key,
				 size_t private_key_length, void *key_id)
{
	/* Fill the whole key-id buffer so no stale bytes trail a short handle
	 * (a PSA key id is narrower than CONFIG_LIBEDHOC_KEY_ID_LEN). */
	memset(key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

	switch (key_import) {
	case HS_KEY_RAW_ED25519:
		/* mbedTLS/PSA has no software EdDSA: the suite exports the seed
		 * and signs with Compact25519, so store it as a RAW_DATA key. */
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
		break;

	case HS_KEY_ECDSA_SHA256:
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_ECDSA(PSA_ALG_SHA_256));
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		break;

	case HS_KEY_ECDSA_SHA384:
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_ECDSA(PSA_ALG_SHA_384));
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		break;

	case HS_KEY_ECDH_P256:
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		break;

	case HS_KEY_ML_DSA_44:
		/* The post-quantum signing key is loaded into the suite's own
		 * software keystore, not PSA; the import symbol exists only when
		 * that suite is compiled in. */
#if defined(CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE) && \
	CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE
		if (EDHOC_SUCCESS !=
		    edhoc_cipher_suite_pqc_1_import_signing_key(
			    private_key, private_key_length, key_id)) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		return EDHOC_SUCCESS;
#else
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
#endif

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	psa_key_id_t psa_key_identifier = PSA_KEY_ID_NULL;

	if (PSA_SUCCESS != psa_import_key(&attributes, private_key,
					  private_key_length,
					  &psa_key_identifier)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	memcpy(key_id, &psa_key_identifier, sizeof(psa_key_identifier));
	return EDHOC_SUCCESS;
}

static int hs_thumbprint_hash(int32_t cose_algorithm, const uint8_t *data,
			      size_t data_length, uint8_t *hash,
			      size_t hash_size, size_t *hash_length)
{
	/* The x5t thumbprint hash is governed by the COSE algorithm declared in
	 * the credential (RFC 9528: 3.5.3), not by the cipher suite. */
	psa_algorithm_t psa_algorithm = PSA_ALG_NONE;

	switch (cose_algorithm) {
	case HS_COSE_ALG_SHA_256_64:
		psa_algorithm = PSA_ALG_SHA_256;
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (PSA_SUCCESS != psa_hash_compute(psa_algorithm, data, data_length,
					    hash, hash_size, hash_length)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int hs_cred_select_local(void *user_context,
			 const struct edhoc_call_context *call_ctx,
			 struct edhoc_credential_selected *selected)
{
	const struct handshake_endpoint *endpoint = user_context;

	if (NULL == endpoint || NULL == endpoint->own || NULL == call_ctx ||
	    NULL == selected) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (endpoint->role != call_ctx->role ||
	    endpoint->expected_cipher_suite !=
		    call_ctx->selected_cipher_suite) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	const struct hs_identity *identity = endpoint->own;

	selected->asymmetric.label = identity->cose_header;

	switch (identity->cose_header) {
	case EDHOC_COSE_HEADER_KID:
		selected->asymmetric.kid.identifier.value = identity->kid;
		selected->asymmetric.kid.identifier.length =
			identity->kid_length;
		selected->asymmetric.kid.credential.value =
			identity->credential;
		selected->asymmetric.kid.credential.length =
			identity->credential_length;
		selected->asymmetric.kid.format = identity->credential_format;

		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		selected->asymmetric.x509_chain.count = identity->cert_count;

		for (size_t i = 0; i < identity->cert_count; ++i) {
			selected->asymmetric.x509_chain.certificate[i].value =
				identity->cert[i].pointer;
			selected->asymmetric.x509_chain.certificate[i].length =
				identity->cert[i].length;
		}

		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		selected->asymmetric.x509_hash.certificate.value =
			identity->cert[0].pointer;
		selected->asymmetric.x509_hash.certificate.length =
			identity->cert[0].length;
		selected->asymmetric.x509_hash.fingerprint.value =
			identity->thumbprint;
		selected->asymmetric.x509_hash.fingerprint.length =
			identity->thumbprint_length;
		selected->asymmetric.x509_hash.algorithm.encode_type =
			EDHOC_ENCODE_TYPE_INTEGER;
		selected->asymmetric.x509_hash.algorithm.integer =
			identity->thumbprint_algorithm;

		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	return hs_import_private_key(identity->key_import,
				     identity->private_key,
				     identity->private_key_length,
				     selected->asymmetric.private_key_id);
}

int hs_cred_authenticate_peer(void *user_context,
			      const struct edhoc_call_context *call_context,
			      const struct edhoc_credential_received *received,
			      struct edhoc_credential_trusted *trusted)
{
	const struct handshake_endpoint *endpoint = user_context;

	if (NULL == endpoint || NULL == endpoint->peer ||
	    NULL == call_context || NULL == received || NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (endpoint->role != call_context->role ||
	    endpoint->expected_cipher_suite !=
		    call_context->selected_cipher_suite) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	const struct hs_identity *identity = endpoint->peer;

	if (identity->cose_header != received->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	switch (identity->cose_header) {
	case EDHOC_COSE_HEADER_KID: {
		if (identity->kid_length != received->kid.identifier.length) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		/* An empty identifier is legal, and memcmp() may not be called
		 * with a null pointer even for zero bytes. */
		if (0 != identity->kid_length &&
		    0 != memcmp(identity->kid, received->kid.identifier.value,
				identity->kid_length)) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		/* The identifier alone selects CRED; nothing else is sent. */
		trusted->asymmetric.credential.value = identity->credential;
		trusted->asymmetric.credential.length =
			identity->credential_length;
		trusted->asymmetric.format = identity->credential_format;
		break;
	}

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		if (identity->cert_count != received->x509_chain.count) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		for (size_t i = 0; i < identity->cert_count; ++i) {
			if (received->x509_chain.certificate[i].length !=
			    identity->cert[i].length) {
				return EDHOC_ERROR_CREDENTIALS_FAILURE;
			}

			if (0 !=
			    memcmp(identity->cert[i].pointer,
				   received->x509_chain.certificate[i].value,
				   identity->cert[i].length)) {
				return EDHOC_ERROR_CREDENTIALS_FAILURE;
			}
		}

		/* CRED is the received end-entity certificate. */
		trusted->asymmetric.credential =
			received->x509_chain.certificate[0];
		trusted->asymmetric.format = EDHOC_CREDENTIAL_FORMAT_RAW;
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH: {
		if (EDHOC_ENCODE_TYPE_INTEGER !=
		    received->x509_hash.algorithm.encode_type) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		if (identity->thumbprint_algorithm !=
		    received->x509_hash.algorithm.integer) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		uint8_t hash[HS_THUMBPRINT_HASH_MAX] = { 0 };
		size_t hash_length = 0;

		const int hash_ret = hs_thumbprint_hash(
			identity->thumbprint_algorithm,
			identity->cert[0].pointer, identity->cert[0].length,
			hash, sizeof(hash), &hash_length);

		if (EDHOC_SUCCESS != hash_ret) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		if (identity->thumbprint_length > hash_length) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		if (identity->thumbprint_length !=
		    received->x509_hash.fingerprint.length) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		if (0 != memcmp(hash, received->x509_hash.fingerprint.value,
				identity->thumbprint_length)) {
			return EDHOC_ERROR_CREDENTIALS_FAILURE;
		}

		trusted->asymmetric.credential.value =
			identity->cert[0].pointer;
		trusted->asymmetric.credential.length =
			identity->cert[0].length;
		trusted->asymmetric.format = EDHOC_CREDENTIAL_FORMAT_RAW;

		break;
	}

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	trusted->asymmetric.public_key.value = identity->public_key;
	trusted->asymmetric.public_key.length = identity->public_key_length;

	return EDHOC_SUCCESS;
}
