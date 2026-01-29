/**
 * \file    edhoc_cipher_suite_2.c
 * \author  Kamil Kielbasa
 * \brief   Example implementation of cipher suite 2.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test header: */
#include "edhoc_cipher_suite_2.h"

/* Standard library header: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* EDHOC headers: */
#include "edhoc_crypto.h"
#include "edhoc_values.h"
#include "edhoc_macros.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* mbedTLS headers: */
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Ellipic curve poin decompression.
 * 
 */
static int mbedtls_ecp_decompress(const mbedtls_ecp_group *grp,
				  const uint8_t *raw_key, size_t raw_key_len,
				  uint8_t *decomp_key, size_t decomp_key_size,
				  size_t *decomp_key_len);

/* Static function definitions --------------------------------------------- */

static int mbedtls_ecp_decompress(const mbedtls_ecp_group *grp,
				  const uint8_t *raw_key, size_t raw_key_len,
				  uint8_t *decomp_key, size_t decomp_key_size,
				  size_t *decomp_key_len)
{
	int ret = 0;

	const size_t p_len = mbedtls_mpi_size(&grp->P);

	*decomp_key_len = (2 * p_len) + 1;

	if (decomp_key_size < *decomp_key_len) {
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	/* decomp_key will consist of 0x04|X|Y */
	(void)memcpy(&decomp_key[1], raw_key, raw_key_len);
	decomp_key[0] = 0x04;

	mbedtls_mpi r;
	mbedtls_mpi x;
	mbedtls_mpi n;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&x);
	mbedtls_mpi_init(&n);

	/* x <= raw_key */
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, raw_key, p_len));

	/* r = x^2 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &x, &x));

	/* r = x^2 + ad */
	if (NULL == grp->A.MBEDTLS_PRIVATE(p)) {
		// Special case where ad is -3
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
	} else {
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
	}

	/* r = x^3 + ax */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

	/* r = x^3 + ax + b */
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

	/* 
	 * Calculate square root of r over finite field P:
	 *   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)
	 */

	/* n = P + 1 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

	/* n = (P + 1) / 4 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

	/* r ^ ((P + 1) / 4) (mod p) */
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

	/* Select solution that has the correct "sign" (equals odd/even solution in finite group) */
	if ((raw_key[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
		/* r = p - r */
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
	}

	/* y => decomp_key */
	ret = mbedtls_mpi_write_binary(&r, decomp_key + 1 + p_len, p_len);

// cppcheck-suppress unusedLabel
cleanup:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&x);
	mbedtls_mpi_free(&n);

	return (ret);
}

/* Module interface function definitions ----------------------------------- */

int edhoc_cipher_suite_2_key_import(void *user_ctx, enum edhoc_key_type key_type,
			      const uint8_t *raw_key, size_t raw_key_len,
			      void *kid)
{
	(void)user_ctx;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/*
         * 1. Generate key attr
         */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

	switch (key_type) {
	case EDHOC_KT_MAKE_KEY_PAIR:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(
						PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(ECC_COMP_KEY_LEN));
		break;

	case EDHOC_KT_KEY_AGREEMENT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(
						PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(ECC_COMP_KEY_LEN));
		break;

	case EDHOC_KT_SIGNATURE:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE |
						       PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(
						PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(ECC_COMP_KEY_LEN));
		break;

	case EDHOC_KT_VERIFY:
		psa_set_key_usage_flags(&attr,
					PSA_KEY_USAGE_VERIFY_MESSAGE |
						PSA_KEY_USAGE_VERIFY_HASH);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(
						PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(ECC_COMP_KEY_LEN));
		break;

	case EDHOC_KT_EXTRACT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr,
				      PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
		psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_EXPAND:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr,
				      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
		psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_ENCRYPT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
		psa_set_key_algorithm(
			&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM,
							       AEAD_TAG_LEN));
		psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(AEAD_KEY_LEN));
		break;

	case EDHOC_KT_DECRYPT:
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(
			&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM,
							       AEAD_TAG_LEN));
		psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(AEAD_KEY_LEN));
		break;

	default:
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/*
         * 2. Import key identifier
         */
	psa_key_id_t *psa_kid = kid;
	*psa_kid = PSA_KEY_HANDLE_INIT;

	if (EDHOC_KT_MAKE_KEY_PAIR == key_type) {
		ret = psa_generate_key(&attr, psa_kid);
	} else {
		ret = psa_import_key(&attr, raw_key, raw_key_len, psa_kid);
	}

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_key_destroy(void *user_ctx, void *kid)
{
	(void)user_ctx;

	if (NULL == kid)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	psa_key_id_t *psa_kid = kid;
	const psa_status_t ret = psa_destroy_key(*psa_kid);
	*psa_kid = PSA_KEY_HANDLE_INIT;

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_make_key_pair(void *user_ctx, const void *kid,
				 uint8_t *restrict priv_key,
				 size_t priv_key_size,
				 size_t *restrict priv_key_len,
				 uint8_t *restrict pub_key, size_t pub_key_size,
				 size_t *restrict pub_key_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == priv_key || 0 == priv_key_size ||
	    NULL == priv_key_len || NULL == pub_key || 0 == pub_key_size ||
	    NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (ECC_COMP_KEY_LEN != priv_key_size ||
	    ECC_COMP_KEY_LEN != pub_key_size)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	const psa_key_id_t *psa_kid = kid;

	ret = psa_export_key(*psa_kid, priv_key, priv_key_size, priv_key_len);

	if (PSA_SUCCESS != ret || ECC_COMP_KEY_LEN != *priv_key_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	uint8_t uncomp_pub_key[ECC_UNCOMP_KEY_LEN] = { 0 };
	ret = psa_export_public_key(*psa_kid, uncomp_pub_key,
				    sizeof(uncomp_pub_key), pub_key_len);

	if (PSA_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	const size_t offset = 1;
	memcpy(pub_key, &uncomp_pub_key[offset], pub_key_size);
	*pub_key_len = pub_key_size;

	return EDHOC_SUCCESS;
}

int edhoc_cipher_suite_2_key_agreement(void *user_ctx, const void *kid,
				 const uint8_t *peer_pub_key,
				 size_t peer_pub_key_len, uint8_t *shr_sec,
				 size_t shr_sec_size, size_t *shr_sec_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == peer_pub_key || 0 == peer_pub_key_len ||
	    NULL == shr_sec || 0 == shr_sec_size || NULL == shr_sec_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (ECC_COMP_KEY_LEN != peer_pub_key_len ||
	    ECC_ECDH_KEY_AGREEMENT_LEN != shr_sec_size)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;

	size_t decom_pub_key_len = 0;
	uint8_t decom_pub_key[ECC_UNCOMP_KEY_LEN] = { 0 };

	mbedtls_pk_context pub_key_ctx = { 0 };
	mbedtls_pk_init(&pub_key_ctx);

	ret = mbedtls_pk_setup(&pub_key_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

	if (PSA_SUCCESS != ret) {
		mbedtls_pk_free(&pub_key_ctx);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = mbedtls_ecp_group_load(
		&mbedtls_pk_ec(pub_key_ctx)->MBEDTLS_PRIVATE(grp),
		MBEDTLS_ECP_DP_SECP256R1);

	if (PSA_SUCCESS != ret) {
		mbedtls_pk_free(&pub_key_ctx);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = mbedtls_ecp_decompress(
		&mbedtls_pk_ec(pub_key_ctx)->MBEDTLS_PRIVATE(grp), peer_pub_key,
		peer_pub_key_len, decom_pub_key, ARRAY_SIZE(decom_pub_key),
		&decom_pub_key_len);

	if (PSA_SUCCESS != ret) {
		mbedtls_pk_free(&pub_key_ctx);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	mbedtls_pk_free(&pub_key_ctx);

	const psa_key_id_t *psa_kid = kid;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);

	if (PSA_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	const psa_algorithm_t alg = psa_get_key_algorithm(&attr);

	ret = psa_raw_key_agreement(alg, *psa_kid, decom_pub_key,
				    decom_pub_key_len, shr_sec, shr_sec_size,
				    shr_sec_len);

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_signature(void *user_ctx, const void *kid,
			     const uint8_t *input, size_t input_len,
			     uint8_t *sign, size_t sign_size, size_t *sign_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == input || 0 == input_len || NULL == sign ||
	    0 == sign_size || NULL == sign_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (ECC_ECDSA_SIGN_LEN != sign_size)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	const psa_key_id_t *psa_kid = kid;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);

	if (PSA_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = psa_sign_message(*psa_kid, psa_get_key_algorithm(&attr), input,
			       input_len, sign, sign_size, sign_len);

	if (ECC_ECDSA_SIGN_LEN != *sign_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_verify(void *user_ctx, const void *kid, const uint8_t *input,
			  size_t input_len, const uint8_t *sign,
			  size_t sign_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == input || 0 == input_len || NULL == sign ||
	    0 == sign_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (ECC_ECDSA_SIGN_LEN != sign_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	const psa_key_id_t *psa_kid = kid;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);

	if (PSA_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = psa_verify_message(*psa_kid, psa_get_key_algorithm(&attr), input,
				 input_len, sign, sign_len);

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_extract(void *user_ctx, const void *kid, const uint8_t *salt,
			   size_t salt_len, uint8_t *prk, size_t prk_size,
			   size_t *prk_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == salt || 0 == salt_len || NULL == prk ||
	    0 == prk_size || NULL == prk_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;

	const psa_key_id_t psa_kid = *((const psa_key_id_t *)kid);
	psa_key_derivation_operation_t ctx = PSA_KEY_DERIVATION_OPERATION_INIT;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(psa_kid, &attr);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_setup(&ctx, psa_get_key_algorithm(&attr));
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_input_bytes(
		&ctx, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_input_key(
		&ctx, PSA_KEY_DERIVATION_INPUT_SECRET, psa_kid);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_set_capacity(&ctx, prk_size);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_output_bytes(&ctx, prk, prk_size);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	*prk_len = prk_size;
	psa_key_derivation_abort(&ctx);

	return EDHOC_SUCCESS;

psa_error:
	psa_key_derivation_abort(&ctx);
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_expand(void *user_ctx, const void *kid, const uint8_t *info,
			  size_t info_len, uint8_t *okm, size_t okm_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == info || 0 == info_len || NULL == okm ||
	    0 == okm_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;

	const psa_key_id_t psa_kid = *((const psa_key_id_t *)kid);
	psa_key_derivation_operation_t ctx = PSA_KEY_DERIVATION_OPERATION_INIT;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(psa_kid, &attr);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_setup(&ctx, psa_get_key_algorithm(&attr));
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_input_key(
		&ctx, PSA_KEY_DERIVATION_INPUT_SECRET, psa_kid);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_input_bytes(
		&ctx, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_set_capacity(&ctx, okm_len);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	ret = psa_key_derivation_output_bytes(&ctx, okm, okm_len);
	if (PSA_SUCCESS != ret)
		goto psa_error;

	psa_key_derivation_abort(&ctx);
	return EDHOC_SUCCESS;

psa_error:
	psa_key_derivation_abort(&ctx);
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_encrypt(void *user_ctx, const void *kid,
			   const uint8_t *nonce, size_t nonce_len,
			   const uint8_t *ad, size_t ad_len,
			   const uint8_t *ptxt, size_t ptxt_len, uint8_t *ctxt,
			   size_t ctxt_size, size_t *ctxt_len)
{
	(void)user_ctx;

	/* Plaintext might be zero length buffer. */
	if (NULL == kid || NULL == nonce || 0 == nonce_len || NULL == ad ||
	    0 == ad_len || NULL == ctxt || 0 == ctxt_size || NULL == ctxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	const psa_key_id_t *psa_kid = kid;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);

	if (PSA_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = psa_aead_encrypt(*psa_kid, psa_get_key_algorithm(&attr), nonce,
			       nonce_len, ad, ad_len, ptxt, ptxt_len, ctxt,
			       ctxt_size, ctxt_len);

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_decrypt(void *user_ctx, const void *kid,
			   const uint8_t *nonce, size_t nonce_len,
			   const uint8_t *ad, size_t ad_len,
			   const uint8_t *ctxt, size_t ctxt_len, uint8_t *ptxt,
			   size_t ptxt_size, size_t *ptxt_len)
{
	(void)user_ctx;

	/* Plaintext might be zero length buffer. */
	if (NULL == kid || NULL == nonce || 0 == nonce_len || NULL == ad ||
	    0 == ad_len || NULL == ctxt || 0 == ctxt_len || NULL == ptxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	const psa_key_id_t *psa_kid = kid;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ret = psa_get_key_attributes(*psa_kid, &attr);

	if (PSA_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = psa_aead_decrypt(*psa_kid, psa_get_key_algorithm(&attr), nonce,
			       nonce_len, ad, ad_len, ctxt, ctxt_len, ptxt,
			       ptxt_size, ptxt_len);

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

int edhoc_cipher_suite_2_hash(void *user_ctx, const uint8_t *input, size_t input_len,
			uint8_t *hash, size_t hash_size, size_t *hash_len)
{
	(void)user_ctx;

	if (NULL == input || 0 == input_len || NULL == hash || 0 == hash_size ||
	    NULL == hash_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	const psa_status_t ret = psa_hash_compute(
		PSA_ALG_SHA_256, input, input_len, hash, hash_size, hash_len);

	return (PSA_SUCCESS == ret) ? EDHOC_SUCCESS :
				      EDHOC_ERROR_CRYPTO_FAILURE;
}

/* Module interface variables and constants -------------------------------- */

static const struct edhoc_keys edhoc_cipher_suite_2_keys = {
	.import_key = edhoc_cipher_suite_2_key_import,
	.destroy_key = edhoc_cipher_suite_2_key_destroy,
};

static const struct edhoc_crypto edhoc_cipher_suite_2_crypto = {
	.make_key_pair = edhoc_cipher_suite_2_make_key_pair,
	.key_agreement = edhoc_cipher_suite_2_key_agreement,
	.signature = edhoc_cipher_suite_2_signature,
	.verify = edhoc_cipher_suite_2_verify,
	.extract = edhoc_cipher_suite_2_extract,
	.expand = edhoc_cipher_suite_2_expand,
	.encrypt = edhoc_cipher_suite_2_encrypt,
	.decrypt = edhoc_cipher_suite_2_decrypt,
	.hash = edhoc_cipher_suite_2_hash,
};

const struct edhoc_keys *edhoc_cipher_suite_2_get_keys(void)
{
	return &edhoc_cipher_suite_2_keys;
}

const struct edhoc_crypto *edhoc_cipher_suite_2_get_crypto(void)
{
	return &edhoc_cipher_suite_2_crypto;
}
