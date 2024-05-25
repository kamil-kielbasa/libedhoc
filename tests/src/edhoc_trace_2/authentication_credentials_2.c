/**
 * \file    authentication_credentials_2.c
 * \author  Kamil Kielbasa
 * \brief   Example implementation of authentication credentials callbacks.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "edhoc_trace_2/authentication_credentials_2.h"
#include "edhoc_trace_2/test_vector_2.h"
#include "cipher_suites/cipher_suite_2.h"

/* Standard library headers: */
#include <stdio.h>
#include <string.h>

/* EDHOC headers: */
#include "edhoc_credentials.h"
#include "edhoc_values.h"
#include "edhoc_macros.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Helper function for printing arrays.
 */
static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length);

/* Static function definitions --------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length)
{
	printf("%s:\tLEN( %zu )\n", name, buffer_length);

	for (size_t i = 0; i < buffer_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", buffer[i]);
	}

	printf("\n\n");
}

/* Module interface function definitions ----------------------------------- */

int auth_cred_fetch_init_2(void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.cred = CRED_I;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_I);
	auth_cred->key_id.cred_is_cbor = true;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_I_cborised,
	       ARRAY_SIZE(ID_CRED_I_cborised));
	auth_cred->key_id.key_id_bstr_length = ARRAY_SIZE(ID_CRED_I_cborised);

	const int ret = cipher_suite_2_key_generate(EDHOC_KT_KEY_AGREEMENT,
						    SK_I, ARRAY_SIZE(SK_I),
						    auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_fetch_resp_2(void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.cred = CRED_R;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_R);
	auth_cred->key_id.cred_is_cbor = true;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_R_cborised,
	       ARRAY_SIZE(ID_CRED_R_cborised));
	auth_cred->key_id.key_id_bstr_length = ARRAY_SIZE(ID_CRED_R_cborised);

	const int ret = cipher_suite_2_key_generate(EDHOC_KT_KEY_AGREEMENT,
						    SK_R, ARRAY_SIZE(SK_R),
						    auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_verify_init_2(void *user_ctx, struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key_ref, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (EDHOC_ENCODE_TYPE_INTEGER != auth_cred->key_id.encode_type)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ID_CRED_R_raw != auth_cred->key_id.key_id_int)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	auth_cred->key_id.key_id_bstr_length = ARRAY_SIZE(ID_CRED_R_cborised);
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_R_cborised,
	       ARRAY_SIZE(ID_CRED_R_cborised));

	auth_cred->key_id.cred = CRED_R;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_R);
	auth_cred->key_id.cred_is_cbor = true;

	*pub_key_ref = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

int auth_cred_verify_resp_2(void *user_ctx, struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key_ref, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (EDHOC_ENCODE_TYPE_INTEGER != auth_cred->key_id.encode_type)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ID_CRED_I_raw != auth_cred->key_id.key_id_int)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	auth_cred->key_id.key_id_bstr_length = ARRAY_SIZE(ID_CRED_I_cborised);
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_I_cborised,
	       ARRAY_SIZE(ID_CRED_I_cborised));

	auth_cred->key_id.cred = CRED_I;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_I);
	auth_cred->key_id.cred_is_cbor = true;

	*pub_key_ref = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}
