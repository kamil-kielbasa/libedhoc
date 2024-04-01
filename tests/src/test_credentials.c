/**
 * @file    test_credentials.c
 * @author  Kamil Kielbasa
 * @brief   Test credentialss for EDHOC.
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "test_credentials.h"
#include "edhoc.h"
#include "test_crypto.h"
#include "test_vectors_p256_v16.h"

/* standard library headers: */
#include <stdio.h>
#include <string.h>

/* crypto headers: */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <psa/crypto.h>
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

struct deser_sign_ctx_s {
	uint8_t *seek;
	uint8_t *end;
	int unit_size;
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

static void print_array(const char *name, const uint8_t *arr, size_t arr_len);

static void deser_sign_ctx_init(struct deser_sign_ctx_s *ctx, uint8_t *seek,
				uint8_t *end, int unit_size);

static int deser_sign_cb(void *void_ctx, int tag, unsigned char *start,
			 size_t len);

static int find_pk_cb(void *void_ppk, int tag, unsigned char *start,
		      size_t len);

static int parse_x509_cert(const uint8_t *cert, size_t cert_len,
			   const uint8_t **pub_key, size_t *pub_key_len);

/* Static function definitions --------------------------------------------- */

static void print_array(const char *name, const uint8_t *arr, size_t arr_len)
{
	printf("%s:\tLEN( %zu )\n", name, arr_len);

	for (size_t i = 0; i < arr_len; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", arr[i]);
	}

	printf("\n\n");
}

static void deser_sign_ctx_init(struct deser_sign_ctx_s *ctx, uint8_t *seek,
				uint8_t *end, int unit_size)
{
	ctx->seek = seek;
	ctx->end = end;
	ctx->unit_size = unit_size;
}

static int deser_sign_cb(void *void_ctx, int tag, unsigned char *start,
			 size_t len)
{
	if (tag == MBEDTLS_ASN1_INTEGER) {
		struct deser_sign_ctx_s *ctx = void_ctx;
		uint8_t *unit_end = ctx->seek + ctx->unit_size;
		if (unit_end <= ctx->end) {
			memcpy(ctx->seek, start + len - ctx->unit_size,
			       (uint32_t)ctx->unit_size);
			ctx->seek = unit_end;
		}
	}

	return 0;
}

static int find_pk_cb(void *void_ppk, int tag, unsigned char *start, size_t len)
{
	(void)len;

	if (tag == MBEDTLS_ASN1_BIT_STRING) {
		uint8_t **pk = void_ppk;
		*pk = start;
	}
	return 0;
}

static int parse_x509_cert(const uint8_t *cert, size_t cert_len,
			   const uint8_t **pub_key, size_t *pub_key_len)
{
	printf("Start parsing an ASN.1 certificate\n");

	mbedtls_x509_crt m_cert = { 0 };
	mbedtls_x509_crt_init(&m_cert);

	/* parse the certificate */
	mbedtls_x509_crt_parse_der_nocopy(&m_cert, cert, cert_len);

	/* write details about the issuer */
	/* and find CN (Common Name), further referred to as "issuer_id" */
	const mbedtls_x509_name *p = &m_cert.issuer;

	const char *short_name = NULL;
	const mbedtls_asn1_buf *issuer_id = NULL;

	while (p) {
		mbedtls_oid_get_attr_short_name(&p->oid, &short_name);
		printf("        %s: %.*s\n", short_name, (int)p->val.len,
		       p->val.p);
		if (0 == MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &p->oid)) {
			issuer_id = &p->val;
		}
		p = p->next;
	};

	print_array("cert issuer_id", issuer_id->p, (uint32_t)issuer_id->len);

	/* make sure it is ECDSA */
	if (MBEDTLS_PK_ECDSA != m_cert.MBEDTLS_PRIVATE(sig_pk)) {
		mbedtls_x509_crt_free(&m_cert);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* check hash algorithm and init signature buffer */
	const mbedtls_md_info_t *md_info =
		mbedtls_md_info_from_type(m_cert.MBEDTLS_PRIVATE(sig_md));
	if (NULL == md_info) {
		printf("mbedtls_md_info_from_type(%d) : not found\n",
		       m_cert.MBEDTLS_PRIVATE(sig_md));
		mbedtls_x509_crt_free(&m_cert);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	const size_t hash_len = mbedtls_md_get_size(md_info);
	uint8_t sign[64] = { 0 };

	/* deserialize signature from ASN.1 to raw concatenation of (R, S) */
	{
		uint8_t *pp = m_cert.MBEDTLS_PRIVATE(sig.p);
		struct deser_sign_ctx_s deser_sign_ctx;
		deser_sign_ctx_init(&deser_sign_ctx, sign,
				    &sign[ARRAY_SIZE(sign)], hash_len);
		mbedtls_asn1_traverse_sequence_of(
			&pp, pp + m_cert.MBEDTLS_PRIVATE(sig.len), 0, 0, 0, 0,
			deser_sign_cb, &deser_sign_ctx);
		print_array("Certificate signature", sign, ARRAY_SIZE(sign));
	}

	psa_key_id_t key_identifier = PSA_KEY_HANDLE_INIT;
	int ret = edhoc_keys_generate(EDHOC_KT_VERIFY, test_vector_1_ca_r_pk,
				      ARRAY_SIZE(test_vector_1_ca_r_pk),
				      &key_identifier);

	if (0 != ret) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	print_array("sign", sign, ARRAY_SIZE(sign));
	print_array("cert", m_cert.tbs.p, (uint32_t)m_cert.tbs.len);
	print_array("pk", test_vector_1_ca_r_pk,
		    ARRAY_SIZE(test_vector_1_ca_r_pk));

	ret = test_crypto_verify(&key_identifier, m_cert.tbs.p,
				 (uint32_t)m_cert.tbs.len, sign,
				 ARRAY_SIZE(sign));

	if (0 == ret) {
		/* export the public key from certificate */
		uint8_t *cpk = NULL;
		size_t cpk_len = 0;
		uint8_t *pp = m_cert.pk_raw.p;
		mbedtls_asn1_traverse_sequence_of(&pp, pp + m_cert.pk_raw.len,
						  0, 0, 0, 0, find_pk_cb, &cpk);
		if (cpk) {
			if (*cpk == 0) {
				++cpk;
			}
			cpk_len = m_cert.pk_raw.len -
				  (size_t)(cpk - m_cert.pk_raw.p);
		}

		*pub_key = cpk;
		*pub_key_len = cpk_len;

		print_array("pk from cert", *pub_key, *pub_key_len);

		mbedtls_x509_crt_free(&m_cert);

		return EDHOC_SUCCESS;
	}

	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

/* Module interface function definitions ----------------------------------- */

int test_cred_fetch_init_x509_chain(void *user_ctx,
				    struct edhoc_auth_creds *auth_creds)
{
	(void)user_ctx;

	if (NULL == auth_creds)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_CHAIN != test_vector_1_id_cred_i[2])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	const uint8_t *cred = &test_vector_1_id_cred_i[6];
	const size_t cred_len = ARRAY_SIZE(test_vector_1_id_cred_i) - 6;

	auth_creds->label = test_vector_1_id_cred_i[2];
	auth_creds->x509_chain.cert = cred;
	auth_creds->x509_chain.cert_len = cred_len;

	if (EDHOC_SUCCESS !=
	    edhoc_keys_generate(EDHOC_KT_SIGN, test_vector_1_sk_i_raw,
				ARRAY_SIZE(test_vector_1_sk_i_raw),
				auth_creds->priv_key_id))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int test_cred_fetch_resp_x509_chain(void *user_ctx,
				    struct edhoc_auth_creds *auth_creds)
{
	(void)user_ctx;

	if (NULL == auth_creds)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_CHAIN != test_vector_1_id_cred_r[2])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	const uint8_t *cred = &test_vector_1_id_cred_r[6];
	const size_t cred_len = ARRAY_SIZE(test_vector_1_id_cred_r) - 6;

	auth_creds->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_creds->x509_chain.cert = cred;
	auth_creds->x509_chain.cert_len = cred_len;

	if (EDHOC_SUCCESS !=
	    edhoc_keys_generate(EDHOC_KT_SIGN, test_vector_1_sk_r_raw,
				ARRAY_SIZE(test_vector_1_sk_r_raw),
				auth_creds->priv_key_id))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int test_cred_verify_init_mocked_x509_chain(void *user_ctx,
					    struct edhoc_auth_creds *auth_creds,
					    const uint8_t **pub_key,
					    size_t *pub_key_len)

{
	(void)user_ctx;

	if (NULL == auth_creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ARRAY_SIZE(test_vector_1_id_cred_r) - 6 !=
	    auth_creds->x509_chain.cert_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(auth_creds->x509_chain.cert,
			&test_vector_1_id_cred_r[6],
			auth_creds->x509_chain.cert_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	*pub_key = test_vector_1_pk_r_raw;
	*pub_key_len = ARRAY_SIZE(test_vector_1_pk_r_raw);

	return EDHOC_SUCCESS;
}

int test_cred_verify_resp_mocked_x509_chain(void *user_ctx,
					    struct edhoc_auth_creds *auth_creds,
					    const uint8_t **pub_key,
					    size_t *pub_key_len)

{
	(void)user_ctx;

	if (NULL == auth_creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ARRAY_SIZE(test_vector_1_id_cred_i) - 6 !=
	    auth_creds->x509_chain.cert_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(auth_creds->x509_chain.cert,
			&test_vector_1_id_cred_i[6],
			auth_creds->x509_chain.cert_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	*pub_key = test_vector_1_pk_i_raw;
	*pub_key_len = ARRAY_SIZE(test_vector_1_pk_i_raw);

	return EDHOC_SUCCESS;
}

int test_cred_verify_init_x509_chain(void *user_ctx,
				     struct edhoc_auth_creds *creds,
				     const uint8_t **pub_key,
				     size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (test_vector_1_id_cred_r[2] != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ARRAY_SIZE(test_vector_1_id_cred_r) - 6 !=
	    creds->x509_chain.cert_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(creds->x509_chain.cert, &test_vector_1_id_cred_r[6],
			creds->x509_chain.cert_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return parse_x509_cert(creds->x509_chain.cert,
			       creds->x509_chain.cert_len, pub_key,
			       pub_key_len);
}

int test_cred_verify_resp_x509_chain(void *user_ctx,
				     struct edhoc_auth_creds *creds,
				     const uint8_t **pub_key,
				     size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (test_vector_1_id_cred_i[2] != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ARRAY_SIZE(test_vector_1_id_cred_i) - 6 !=
	    creds->x509_chain.cert_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(creds->x509_chain.cert, &test_vector_1_id_cred_i[6],
			creds->x509_chain.cert_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return parse_x509_cert(creds->x509_chain.cert,
			       creds->x509_chain.cert_len, pub_key,
			       pub_key_len);
}

int test_cred_fetch_init_x509_hash(void *user_ctx,
				   struct edhoc_auth_creds *creds)
{
	(void)user_ctx;

	if (NULL == creds)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (0x2e != test_vector_2_id_cred_i[4])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	creds->label = EDHOC_COSE_HEADER_X509_HASH;
	creds->x509_hash.cert = &test_vector_2_cred_i[3];
	creds->x509_hash.cert_len = ARRAY_SIZE(test_vector_2_cred_i) - 3;
	creds->x509_hash.cert_fp = &test_vector_2_id_cred_i[6];
	creds->x509_hash.cert_fp_len = ARRAY_SIZE(test_vector_2_id_cred_i) - 6;
	creds->x509_hash.alg[0] = -15;
	creds->x509_hash.alg_len = 1;

	if (EDHOC_SUCCESS !=
	    edhoc_keys_generate(EDHOC_KT_SIGN, test_vector_2_sk_i_raw,
				ARRAY_SIZE(test_vector_2_sk_i_raw),
				creds->priv_key_id))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int test_cred_fetch_resp_x509_hash(void *user_ctx,
				   struct edhoc_auth_creds *creds)
{
	(void)user_ctx;

	if (NULL == creds)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (0x2e != test_vector_2_id_cred_r[4])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	creds->label = EDHOC_COSE_HEADER_X509_HASH;
	creds->x509_hash.cert = &test_vector_2_cred_r[3];
	creds->x509_hash.cert_len = ARRAY_SIZE(test_vector_2_cred_r) - 3;
	creds->x509_hash.cert_fp = &test_vector_2_id_cred_r[6];
	creds->x509_hash.cert_fp_len = ARRAY_SIZE(test_vector_2_id_cred_r) - 6;
	creds->x509_hash.alg[0] = -15;
	creds->x509_hash.alg_len = 1;

	if (EDHOC_SUCCESS !=
	    edhoc_keys_generate(EDHOC_KT_SIGN, test_vector_2_sk_r_raw,
				ARRAY_SIZE(test_vector_2_sk_r_raw),
				creds->priv_key_id))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int test_cred_verify_init_mocked_x509_hash(void *user_ctx,
					   struct edhoc_auth_creds *creds,
					   const uint8_t **pub_key,
					   size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_HASH != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };
	const psa_status_t status =
		psa_hash_compute(PSA_ALG_SHA_256, test_vector_2_cred_r,
				 ARRAY_SIZE(test_vector_2_cred_r), hash,
				 ARRAY_SIZE(hash), &hash_len);

	if (PSA_SUCCESS != status || ARRAY_SIZE(hash) != hash_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	uint8_t cert_fp[8] = { 0 };
	memcpy(cert_fp, hash, sizeof(cert_fp));

	if (ARRAY_SIZE(cert_fp) != creds->x509_hash.cert_fp_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 == memcmp(cert_fp, creds->x509_hash.cert_fp,
			creds->x509_hash.cert_fp_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	creds->x509_hash.cert = &test_vector_2_cred_r[3];
	creds->x509_hash.cert_len = ARRAY_SIZE(test_vector_2_cred_r) - 3;

	*pub_key = test_vector_2_pk_r_raw;
	*pub_key_len = ARRAY_SIZE(test_vector_2_pk_r_raw);

	return EDHOC_SUCCESS;
}

int test_cred_verify_resp_mocked_x509_hash(void *user_ctx,
					   struct edhoc_auth_creds *creds,
					   const uint8_t **pub_key,
					   size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_HASH != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };
	const psa_status_t status =
		psa_hash_compute(PSA_ALG_SHA_256, test_vector_2_cred_i,
				 ARRAY_SIZE(test_vector_2_cred_i), hash,
				 ARRAY_SIZE(hash), &hash_len);

	if (PSA_SUCCESS != status || ARRAY_SIZE(hash) != hash_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	uint8_t cert_fp[8] = { 0 };
	memcpy(cert_fp, hash, sizeof(cert_fp));

	if (ARRAY_SIZE(cert_fp) != creds->x509_hash.cert_fp_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 == memcmp(cert_fp, creds->x509_hash.cert_fp,
			creds->x509_hash.cert_fp_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	creds->x509_hash.cert = &test_vector_2_cred_i[3];
	creds->x509_hash.cert_len = ARRAY_SIZE(test_vector_2_cred_i) - 3;

	*pub_key = test_vector_2_pk_i_raw;
	*pub_key_len = ARRAY_SIZE(test_vector_2_pk_i_raw);

	return EDHOC_SUCCESS;
}

int test_cred_verify_init_x509_hash(void *user_ctx,
				    struct edhoc_auth_creds *creds,
				    const uint8_t **pub_key,
				    size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_HASH != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };
	const psa_status_t status =
		psa_hash_compute(PSA_ALG_SHA_256, test_vector_2_cred_r,
				 ARRAY_SIZE(test_vector_2_cred_r), hash,
				 ARRAY_SIZE(hash), &hash_len);

	if (PSA_SUCCESS != status || ARRAY_SIZE(hash) != hash_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	uint8_t cert_fp[8] = { 0 };
	memcpy(cert_fp, hash, sizeof(cert_fp));

	if (ARRAY_SIZE(cert_fp) != creds->x509_hash.cert_fp_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 == memcmp(cert_fp, creds->x509_hash.cert_fp,
			creds->x509_hash.cert_fp_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	creds->x509_hash.cert = &test_vector_2_cred_r[3];
	creds->x509_hash.cert_len = ARRAY_SIZE(test_vector_2_cred_r) - 3;

	return parse_x509_cert(creds->x509_hash.cert, creds->x509_hash.cert_len,
			       pub_key, pub_key_len);
}

/**
 * \brief Credentials verify for initiator for X509 hash authentication method.
 */
int test_cred_verify_resp_x509_hash(void *user_ctx,
				    struct edhoc_auth_creds *creds,
				    const uint8_t **pub_key,
				    size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_X509_HASH != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };
	const psa_status_t status =
		psa_hash_compute(PSA_ALG_SHA_256, test_vector_2_cred_i,
				 ARRAY_SIZE(test_vector_2_cred_i), hash,
				 ARRAY_SIZE(hash), &hash_len);

	if (PSA_SUCCESS != status || ARRAY_SIZE(hash) != hash_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	uint8_t cert_fp[8] = { 0 };
	memcpy(cert_fp, hash, sizeof(cert_fp));

	if (ARRAY_SIZE(cert_fp) != creds->x509_hash.cert_fp_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 == memcmp(cert_fp, creds->x509_hash.cert_fp,
			creds->x509_hash.cert_fp_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	creds->x509_hash.cert = &test_vector_2_cred_i[3];
	creds->x509_hash.cert_len = ARRAY_SIZE(test_vector_2_cred_i) - 3;

	return parse_x509_cert(creds->x509_hash.cert, creds->x509_hash.cert_len,
			       pub_key, pub_key_len);
}

int test_cred_fetch_init_x509_kid(void *user_ctx,
				  struct edhoc_auth_creds *creds)
{
	(void)user_ctx;

	if (NULL == creds)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (0x2b != test_vector_4_id_cred_i[2])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	creds->label = EDHOC_COSE_HEADER_KID;
	creds->key_id.key_id[0] = (int8_t)-12;
	creds->key_id.key_id_len = 1;
	creds->key_id.cred = &test_vector_4_cred_i[3];
	creds->key_id.cred_len = ARRAY_SIZE(test_vector_4_cred_i) - 3;

	if (EDHOC_SUCCESS !=
	    edhoc_keys_generate(EDHOC_KT_SIGN, test_vector_4_sk_i_raw,
				ARRAY_SIZE(test_vector_4_sk_i_raw),
				creds->priv_key_id))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int test_cred_fetch_resp_x509_kid(void *user_ctx,
				  struct edhoc_auth_creds *creds)
{
	(void)user_ctx;

	if (NULL == creds)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (0x32 != test_vector_4_id_cred_r[2])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	creds->label = EDHOC_COSE_HEADER_KID;
	creds->key_id.key_id[0] = (int8_t)-19; // cbor int 0x32
	creds->key_id.key_id_len = 1;
	creds->key_id.cred = &test_vector_4_cred_r[3];
	creds->key_id.cred_len = ARRAY_SIZE(test_vector_4_cred_r) - 3;

	if (EDHOC_SUCCESS !=
	    edhoc_keys_generate(EDHOC_KT_SIGN, test_vector_4_sk_r_raw,
				ARRAY_SIZE(test_vector_4_sk_r_raw),
				creds->priv_key_id))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int test_cred_verify_init_mocked_x509_kid(void *user_ctx,
					  struct edhoc_auth_creds *creds,
					  const uint8_t **pub_key,
					  size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (1 == creds->key_id.key_id_len &&
	    ONE_BYTE_CBOR_INT_MIN_VALUE < (int8_t)creds->key_id.key_id[0] &&
	    ONE_BYTE_CBOR_INT_MAX_VALUE > (int8_t)creds->key_id.key_id[0] &&
	    -19 == (int8_t)creds->key_id.key_id[0]) {
		creds->key_id.cred = &test_vector_4_cred_r[3];
		creds->key_id.cred_len = ARRAY_SIZE(test_vector_4_cred_r) - 3;
		*pub_key = test_vector_4_pk_r_raw;
		*pub_key_len = ARRAY_SIZE(test_vector_4_pk_r_raw);
		return EDHOC_SUCCESS;
	}

	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

int test_cred_verify_resp_mocked_x509_kid(void *user_ctx,
					  struct edhoc_auth_creds *creds,
					  const uint8_t **pub_key,
					  size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (1 == creds->key_id.key_id_len &&
	    ONE_BYTE_CBOR_INT_MIN_VALUE < (int8_t)creds->key_id.key_id[0] &&
	    ONE_BYTE_CBOR_INT_MAX_VALUE > (int8_t)creds->key_id.key_id[0] &&
	    -12 == (int8_t)creds->key_id.key_id[0]) {
		creds->key_id.cred = &test_vector_4_cred_i[3];
		creds->key_id.cred_len = ARRAY_SIZE(test_vector_4_cred_i) - 3;
		*pub_key = test_vector_4_pk_i_raw;
		*pub_key_len = ARRAY_SIZE(test_vector_4_pk_i_raw);
		return EDHOC_SUCCESS;
	}

	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

int test_cred_verify_init_x509_kid(void *user_ctx,
				   struct edhoc_auth_creds *creds,
				   const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (1 == creds->key_id.key_id_len &&
	    ONE_BYTE_CBOR_INT_MIN_VALUE < (int8_t)creds->key_id.key_id[0] &&
	    ONE_BYTE_CBOR_INT_MAX_VALUE > (int8_t)creds->key_id.key_id[0] &&
	    -19 == (int8_t)creds->key_id.key_id[0]) {
		creds->key_id.cred = &test_vector_4_cred_r[3];
		creds->key_id.cred_len = ARRAY_SIZE(test_vector_4_cred_r) - 3;

		return parse_x509_cert(creds->key_id.cred,
				       creds->key_id.cred_len, pub_key,
				       pub_key_len);
	}

	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

int test_cred_verify_resp_x509_kid(void *user_ctx,
				   struct edhoc_auth_creds *creds,
				   const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == creds || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != creds->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (1 == creds->key_id.key_id_len &&
	    ONE_BYTE_CBOR_INT_MIN_VALUE < (int8_t)creds->key_id.key_id[0] &&
	    ONE_BYTE_CBOR_INT_MAX_VALUE > (int8_t)creds->key_id.key_id[0] &&
	    -12 == (int8_t)creds->key_id.key_id[0]) {
		creds->key_id.cred = &test_vector_4_cred_i[3];
		creds->key_id.cred_len = ARRAY_SIZE(test_vector_4_cred_i) - 3;

		return parse_x509_cert(creds->key_id.cred,
				       creds->key_id.cred_len, pub_key,
				       pub_key_len);
	}

	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}