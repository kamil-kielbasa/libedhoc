/**
 * \file    edhoc_message_3.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 3.
 * \version 0.1
 * \date    2024-01-01
 *
 * \copyright Copyright (c) 2024
 *
 */

/* Include files ----------------------------------------------------------- */
#include "edhoc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include <zcbor_common.h>
#include <backend_cbor_message_3_encode.h>
#include <backend_cbor_message_3_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_bstr_type_decode.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_int_type_decode.h>
#include <backend_cbor_id_cred_x_encode.h>
#include <backend_cbor_id_cred_x_decode.h>
#include <backend_cbor_sig_structure_encode.h>
#include <backend_cbor_info_encode.h>
#include <backend_cbor_plaintext_x_decode.h>
#include <backend_cbor_enc_structure_encode.h>
#include <backend_cbor_enc_structure_decode.h>
#include <backend_cbor_ead_encode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/**
 * \brief Helper structure for CBOR encoded elements for context_3.
 */
struct cbor_items {
	bool id_cred_i_is_cob; // cob = cbor one byte
	int32_t id_cred_i_cob_val; // cob = cbor one byte
	uint8_t *id_cred_i;
	size_t id_cred_i_len;

	uint8_t *th_3;
	size_t th_3_len;

	uint8_t *cred_i;
	size_t cred_i_len;

	bool is_ead_3;
	uint8_t *ead_3;
	size_t ead_3_len;

	size_t buf_len;
	uint8_t buf[];
};

/**
 * \brief Helper structure for parsed PLAINTEXT_3.
 */
struct plaintext {
	struct edhoc_auth_creds auth_creds;

	const uint8_t *sign_or_mac;
	size_t sign_or_mac_len;

	const uint8_t *ead;
	size_t ead_len;
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** 
 * \brief CBOR integer overhead.
 *
 * \param val		        Length of buffer to CBOR as int.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_int_overhead(int32_t val);

/** 
 * \brief CBOR text stream overhead.
 *
 * \param len		        Length of buffer to CBOR as tstr.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_tstr_overhead(size_t len);

/** 
 * \brief CBOR byte stream overhead.
 *
 * \param len		        Length of buffer to CBOR as bstr.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_bstr_overhead(size_t len);

/** 
 * \brief CBOR map overhead.
 *
 * \param items		        Number of items for map.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_map_overhead(size_t items);

/** 
 * \brief CBOR array overhead.
 *
 * \param items		        Number of items for array.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_array_overhead(size_t items);

/** 
 * \brief Check if integer might be encoded as CBOR one byte. 
 *
 * \param len		        Length of buffer.
 * \param val                   Value for cbor encoding.
 *
 * \retval True if might be encoded as one byte cbor integer,
 *         otherwise false.
 */
static inline bool is_cbor_one_byte(size_t len, int8_t val);

/**
 * \brief Calculate memory required for input (context_3) for for MAC_3.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 *
 * \retval Value different than 0 on success, otherwise failure.
 */
static size_t calc_mac_3_input_len(const struct edhoc_context *ctx,
				   const struct edhoc_auth_creds *auth_creds);

/**
 * \brief Compute psuedo random key (PRK_4e3m).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int compute_prk_4e3m(struct edhoc_context *ctx);

/**
 * \brief Generate context_3.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[out] cbor_items	Buffer where the generated context_3 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int calc_mac_3_context(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_creds,
			      struct cbor_items *cbor_items);

/**
 * \brief Compute MAC_3.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] cbor_items	Buffer containing the context_3.
 * \param[out] mac_3		Buffer where the generated MAC_3 is to be written.
 * \param mac_3_len		Size of the \p mac_3 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int calc_mac_3(const struct edhoc_context *ctx,
		      const struct cbor_items *cbor_items, uint8_t *mac_3,
		      size_t mac_3_len);

/**
 * \brief Compute Signature_or_MAC_3.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] auth_creds	Authentication credentials.
 * \param[in] cbor_items	Buffer containing the context_3.
 * \param[in] mac_3		Buffer containing the MAC_3.
 * \param mac_3_len		Size of the \p mac_3 buffer in bytes.
 * \param[out] sign		Buffer where the generated signature is to be written.
 * \param sign_len		Size of the \p sign buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_sign_or_mac_3(const struct edhoc_context *ctx,
				 const struct edhoc_auth_creds *auth_creds,
				 const struct cbor_items *cbor_items,
				 const uint8_t *mac_3, size_t mac_3_len,
				 uint8_t *sign, size_t sign_len);

/**
 * \brief Prepare PLAINTEXT_3.
 *
 * \param[in] cbor_items	Buffer containing the context_2.
 * \param[in] sign		Buffer containing the signature.
 * \param sign_len		Size of the \p sign buffer in bytes.
 * \param[out] ptxt	        Buffer where the generated plaintext is to be written.
 * \param ptxt_len	        Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_3(const struct cbor_items *cbor_items,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size);

/**
 * \brief Compute required length in bytes for AAD_3.
 *
 * \param[in] ctx	        EDHOC context.
 *
 * \retval Value different than 0 is success, otherwise failure.
 */
static size_t compute_aad_3_len(const struct edhoc_context *ctx);

/**
 * \brief Compute K_3, IV_3 and AAD_3.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[out] key		Buffer where the generated K_3 is to be written.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[out] iv	        Buffer where the generated IV_3 is to be written.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[out] aad	        Buffer where the generated AAD_3 is to be written.
 * \param aad_len               Size of the \p aad buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_key_iv_aad(const struct edhoc_context *ctx, uint8_t *key,
			      size_t key_len, uint8_t *iv, size_t iv_len,
			      uint8_t *aad, size_t aad_len);

/**
 * \brief Compute K_3, IV_3 and AAD_3.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[in] key		Buffer containing the K_3.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[in] iv	        Buffer containing the IV_3.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[in] aad	        Buffer containing the AAD_3.
 * \param aad_len               Size of the \p aad buffer in bytes.
 * \param[in] ptxt	        Buffer containing the PLAINTEXT_3.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] ctxt	        Buffer where the generated ciphertext is to be written.
 * \param ctxt_size	        Size of the \p ctxt buffer in bytes.
 * \param[out] ctxt_len         On success, the number of bytes that make up the CIPHERTEXT_3.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ptxt, size_t ptxt_len,
			      uint8_t *ctxt, size_t ctxt_size,
			      size_t *ctxt_len);

/**
 * \brief Compute transcript hash 4.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] cbor_items        Structure containing the context_3.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_3.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_th_4(struct edhoc_context *ctx,
			const struct cbor_items *cbor_items,
			const uint8_t *ptxt, size_t ptxt_len);

/**
 * \brief Compute output pseudo random key (PRK_out).
 *
 * \param[in] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_prk_out(struct edhoc_context *ctx);

/**
 * \brief Generate edhoc message 3.
 *
 * \param[in] ctxt	        Buffer continas the ciphertext.
 * \param ctxt_len	        Size of the \p ctxt buffer in bytes.
 * \param[out] msg_3            Buffer where the generated message 3 is to be written.
 * \param msg_3_size            Size of the \p msg_3 buffer in bytes.
 * \param[out] msg_3_len        On success, the number of bytes that make up the message 3.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
		     size_t msg_3_size, size_t *msg_3_len);

/**
 * \brief CBOR decode message 3 and save address and length for CIPHERTEXT_3.
 *
 * \param[in] msg_3     	Buffer containing the message 3.
 * \param msg_3_len     	Size of the \p msg_3 buffer in bytes.
 * \param[out] ctxt	        Pointer to buffer containing the CIPHERTEXT_3.
 * \param[out] ctxt_len	        Size of the \p ctxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_msg_3(const uint8_t *msg_2, size_t msg_2_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len);

/**
 * \brief Decrypt CIPHERTEXT_3.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] key		Buffer containing the K_3.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[in] iv	        Buffer containing the IV_3.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[in] aad	        Buffer containing the AAD_3.
 * \param aad_len               Size of the \p aad buffer in bytes.
 * \param[in] ctxt	        Pointer to buffer containing the CIPHERTEXT_3.
 * \param ctxt_len	        Size of the \p ctxt buffer in bytes.
 * \param[out] ptxt	        Buffer where the decrypted PLAINTEXT_3 is to be written.
 * \param ptxt_len	        Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int decrypt_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ctxt, size_t ctxt_len,
			      uint8_t *ptxt, size_t ptxt_len);

/**
 * \brief Parsed cborised PLAINTEXT_3 for separate buffers.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_3.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] parsed_ptxt     	Structure where parsed PLAINTEXT_3 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt);

/**
 * \brief Verify Signature_or_MAC_3.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] cbor_items        Structure containing the context_3.
 * \param[in] parsed_ptxt     	Structure containing the parsed PLAINTEXT_3.
 * \param[in] pub_key           Buffer containing the public key from peer credentials.
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 * \param[in] mac_3             Buffer containing the MAC_3.
 * \param mac_3_len             Size of the \p mac_3 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int verify_sign_or_mac_3(const struct edhoc_context *ctx,
				const struct cbor_items *cbor_items,
				const struct plaintext *parsed_ptxt,
				const uint8_t *pub_key, size_t pub_key_len,
				const uint8_t *mac_3, size_t mac_3_len);

/* Static function definitions --------------------------------------------- */

#ifdef DEBUG_LOGS
#include <stdio.h>
static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length)
{
	printf("%s:\tLEN( %zu )\n", name, array_length);

	for (size_t i = 0; i < array_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", array[i]);
	}

	printf("\n\n");
}
#define LOG(name, arr, len) print_array(name, arr, len)
#else
#define LOG(name, arr, len) \
	do {                \
		(void)name; \
		(void)arr;  \
		(void)len;  \
	} while (0)
#endif

static inline size_t cbor_int_overhead(int32_t val)
{
	if (val >= ONE_BYTE_CBOR_INT_MIN_VALUE &&
	    val <= ONE_BYTE_CBOR_INT_MAX_VALUE)
		return 1;

	if (val >= -256 && val <= 255)
		return 2;

	return 3;
}

static inline size_t cbor_tstr_overhead(size_t len)
{
	if (len <= 11)
		return 1;
	return 2;
}

static inline size_t cbor_bstr_overhead(size_t len)
{
	if (len <= 5)
		return 1;
	if (len <= UINT8_MAX)
		return 2;
	if (len <= UINT16_MAX)
		return 3;
	return 5;
}

static inline size_t cbor_map_overhead(size_t items)
{
	(void)items;

	return 3;
}

static inline size_t cbor_array_overhead(size_t items)
{
	(void)items;

	return 1;
}

static inline bool is_cbor_one_byte(size_t len, int8_t val)
{
	return (ONE_BYTE_CBOR_INT_LEN == len &&
		ONE_BYTE_CBOR_INT_MIN_VALUE < val &&
		ONE_BYTE_CBOR_INT_MAX_VALUE > val);
}

static size_t calc_mac_3_input_len(const struct edhoc_context *ctx,
				   const struct edhoc_auth_creds *auth_cred)
{
	if (NULL == ctx || NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	const size_t nr_of_items = 1;
	size_t len = 0;

	/* ID_CRED_I. */
	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		len += cbor_map_overhead(nr_of_items);

		if (is_cbor_one_byte(auth_cred->key_id.key_id_len,
				     (int8_t)auth_cred->key_id.key_id[0])) {
			len += cbor_int_overhead(
				(int8_t)auth_cred->key_id.key_id[0]);
		} else {
			len += auth_cred->key_id.key_id_len;
			len += cbor_bstr_overhead(auth_cred->key_id.key_id_len);
		}
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		len += cbor_map_overhead(nr_of_items);
		len += auth_cred->x509_chain.cert_len;
		len += cbor_bstr_overhead(auth_cred->x509_chain.cert_len);
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		len += cbor_map_overhead(nr_of_items);
		len += cbor_array_overhead(nr_of_items);
		if (is_cbor_one_byte(auth_cred->x509_hash.alg_len,
				     (int8_t)auth_cred->x509_hash.alg[0])) {
			len += cbor_int_overhead(
				(int8_t)auth_cred->x509_hash.alg[0]);
		} else {
			len += cbor_bstr_overhead(auth_cred->x509_hash.alg_len);
		}
		len += auth_cred->x509_hash.cert_fp_len;
		len += cbor_bstr_overhead(auth_cred->x509_hash.cert_fp_len);
		break;

	default:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	/* TH_3. */
	len += ctx->th_len;
	len += cbor_bstr_overhead(ctx->th_len);

	/* CRED_I. */
	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		len += auth_cred->key_id.cred_len;
		len += cbor_bstr_overhead(auth_cred->key_id.cred_len);
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		len += auth_cred->x509_chain.cert_len;
		len += cbor_bstr_overhead(auth_cred->x509_chain.cert_len);
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		len += auth_cred->x509_hash.cert_len;
		len += cbor_bstr_overhead(auth_cred->x509_hash.cert_len);
		break;

	default:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	/* EAD_3. */
	for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
		len += cbor_int_overhead(ctx->ead_token[i].label);
		len += ctx->ead_token[i].value_len;
		len += cbor_bstr_overhead(ctx->ead_token[i].value_len);
	}

	return len;
}

static int compute_prk_4e3m(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	switch (ctx->method) {
	case EDHOC_INIT_SIGN_RESP_SIGN:
		ctx->prk_state = EDHOC_PRK_STATE_4E3M;
		return EDHOC_SUCCESS;

	case EDHOC_INIT_SIGN_RESP_STAT:
	case EDHOC_INIT_STAT_RESP_SIGN:
	case EDHOC_INIT_STAT_RESP_STAT:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_ERROR_GENERIC_ERROR;
}

static int calc_mac_3_context(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_cred,
			      struct cbor_items *cbor_items)
{
	if (NULL == ctx || NULL == auth_cred || NULL == cbor_items)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_3 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	const size_t nr_of_items = 1;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* ID_CRED_R length. */
	cbor_items->id_cred_i = &cbor_items->buf[0];

	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		len += cbor_map_overhead(nr_of_items);
		if (is_cbor_one_byte(auth_cred->key_id.key_id_len,
				     (int8_t)auth_cred->key_id.key_id[0])) {
			cbor_items->id_cred_i_is_cob = true;
			len += cbor_int_overhead(
				(int8_t)auth_cred->key_id.key_id[0]);
		} else {
			len += auth_cred->key_id.key_id_len;
			len += cbor_bstr_overhead(auth_cred->key_id.key_id_len);
		}
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		len += cbor_map_overhead(nr_of_items);
		len += auth_cred->x509_chain.cert_len;
		len += cbor_bstr_overhead(auth_cred->x509_chain.cert_len);
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		len += cbor_map_overhead(nr_of_items);
		len += cbor_array_overhead(nr_of_items);
		if (is_cbor_one_byte(auth_cred->x509_hash.alg_len,

				     (int8_t)auth_cred->x509_hash.alg[0])) {
			len += cbor_int_overhead(
				(int8_t)auth_cred->x509_hash.alg[0]);
		} else {
			len += auth_cred->x509_hash.alg_len;
			len += cbor_bstr_overhead(auth_cred->x509_hash.alg_len);
		}
		len += auth_cred->x509_hash.cert_fp_len;
		len += cbor_bstr_overhead(auth_cred->x509_hash.cert_fp_len);
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	cbor_items->id_cred_i_len = len;

	/* Cborise ID_CRED_R. */
	struct id_cred_x cbor_id_cred_i = { 0 };

	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID: {
		cbor_id_cred_i._id_cred_x_kid_present = true;
		if (is_cbor_one_byte(auth_cred->key_id.key_id_len,
				     (int8_t)auth_cred->key_id.key_id[0])) {
			cbor_id_cred_i._id_cred_x_kid._id_cred_x_kid_choice =
				_id_cred_x_kid_int;
			cbor_id_cred_i._id_cred_x_kid._id_cred_x_kid_int =
				(int8_t)auth_cred->key_id.key_id[0];

			if (cbor_items->id_cred_i_is_cob) {
				const int32_t val =
					(int8_t)auth_cred->key_id.key_id[0];

				len = 0;
				ret = cbor_encode_integer_type_int_type(
					(uint8_t *)&cbor_items
						->id_cred_i_cob_val,
					sizeof(cbor_items->id_cred_i_cob_val),
					&val, &len);

				if (ZCBOR_SUCCESS != ret ||
				    ONE_BYTE_CBOR_INT_LEN != len)
					return EDHOC_ERROR_CBOR_FAILURE;
			}
		} else {
			cbor_id_cred_i._id_cred_x_kid._id_cred_x_kid_choice =
				_id_cred_x_kid_bstr;

			cbor_id_cred_i._id_cred_x_kid._id_cred_x_kid_bstr.value =
				auth_cred->key_id.key_id;
			cbor_id_cred_i._id_cred_x_kid._id_cred_x_kid_bstr.len =
				auth_cred->key_id.key_id_len;
		}
		break;
	}
	case EDHOC_COSE_HEADER_X509_CHAIN: {
		cbor_id_cred_i._id_cred_x_x5chain_present = true;
		cbor_id_cred_i._id_cred_x_x5chain._id_cred_x_x5chain.value =
			auth_cred->x509_chain.cert;
		cbor_id_cred_i._id_cred_x_x5chain._id_cred_x_x5chain.len =
			auth_cred->x509_chain.cert_len;
		break;
	}
	case EDHOC_COSE_HEADER_X509_HASH: {
		cbor_id_cred_i._id_cred_x_x5t_present = true;
		cbor_id_cred_i._id_cred_x_x5t._id_cred_x_x5t_hash.value =
			auth_cred->x509_hash.cert_fp;
		cbor_id_cred_i._id_cred_x_x5t._id_cred_x_x5t_hash.len =
			auth_cred->x509_hash.cert_fp_len;

		if (is_cbor_one_byte(auth_cred->x509_hash.alg_len,
				     (int8_t)auth_cred->x509_hash.alg[0])) {
			cbor_id_cred_i._id_cred_x_x5t._id_cred_x_x5t_alg_choice =
				_id_cred_x_x5t_alg_int;
			cbor_id_cred_i._id_cred_x_x5t._id_cred_x_x5t_alg_int =
				(int8_t)auth_cred->x509_hash.alg[0];
		} else {
			cbor_id_cred_i._id_cred_x_x5t._id_cred_x_x5t_alg_choice =
				_id_cred_x_x5t_alg_bstr;
			cbor_id_cred_i._id_cred_x_x5t._id_cred_x_x5t_alg_bstr
				.value = auth_cred->x509_hash.alg;
			cbor_id_cred_i._id_cred_x_x5t._id_cred_x_x5t_alg_bstr
				.len = auth_cred->x509_hash.alg_len;
		}
		break;
	}

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	len = 0;
	ret = cbor_encode_id_cred_x(cbor_items->id_cred_i,
				    cbor_items->id_cred_i_len, &cbor_id_cred_i,
				    &len);
	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	cbor_items->id_cred_i_len = len;

	/* TH_3 length. */
	len = ctx->th_len;
	cbor_items->th_3 = &cbor_items->id_cred_i[cbor_items->id_cred_i_len];
	cbor_items->th_3_len = cbor_bstr_overhead(len) + len;

	/* Cborise TH_3. */
	const struct zcbor_string cbor_th_3 = {
		.value = ctx->th,
		.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		cbor_items->th_3, cbor_items->th_3_len, &cbor_th_3, &len);

	if (ZCBOR_SUCCESS != ret || cbor_items->th_3_len != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* CRED_R length. */
	cbor_items->cred_i = &cbor_items->th_3[cbor_items->th_3_len];
	len = 0;

	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		len += auth_cred->key_id.cred_len;
		len += cbor_bstr_overhead(auth_cred->key_id.cred_len);
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		len += auth_cred->x509_chain.cert_len;
		len += cbor_bstr_overhead(auth_cred->x509_chain.cert_len);
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		len += auth_cred->x509_hash.cert_len;
		len += cbor_bstr_overhead(auth_cred->x509_hash.cert_len);
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	cbor_items->cred_i_len = len;

	/* Cborise CRED_R. */
	struct zcbor_string cbor_cred_i = { 0 };

	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		cbor_cred_i.value = auth_cred->key_id.cred;
		cbor_cred_i.len = auth_cred->key_id.cred_len;
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		cbor_cred_i.value = auth_cred->x509_chain.cert;
		cbor_cred_i.len = auth_cred->x509_chain.cert_len;
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		cbor_cred_i.value = auth_cred->x509_hash.cert;
		cbor_cred_i.len = auth_cred->x509_hash.cert_len;
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		cbor_items->cred_i, cbor_items->cred_i_len, &cbor_cred_i, &len);

	if (ZCBOR_SUCCESS != ret || cbor_items->cred_i_len != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* EAD_3 length. */
	if (0 != ctx->nr_of_ead_tokens) {
		len = 0;
		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			len += cbor_int_overhead(ctx->ead_token[i].label);
			len += 1; // cbor boolean
			len += ctx->ead_token[i].value_len;
			len += cbor_bstr_overhead(ctx->ead_token[i].value_len);
		}

		cbor_items->is_ead_3 = true;
		cbor_items->ead_3 = &cbor_items->cred_i[cbor_items->cred_i_len];
		cbor_items->ead_3_len = len;
	} else {
		cbor_items->is_ead_3 = false;
		cbor_items->ead_3 = NULL;
		cbor_items->ead_3_len = 0;
	}

	/* Cborise EAD_3 if present. */
	if (true == cbor_items->is_ead_3) {
		struct ead_ ead_tokens = { ._ead_count =
						   ctx->nr_of_ead_tokens };

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ead_tokens._ead[i]._ead_label = ctx->ead_token[i].label;
			ead_tokens._ead[i]._ead_value_present =
				(NULL != ctx->ead_token[i].value);
			ead_tokens._ead[i]._ead_value.value =
				ctx->ead_token[i].value;
			ead_tokens._ead[i]._ead_value.len =
				ctx->ead_token[i].value_len;
		}

		len = 0;
		ret = cbor_encode_ead(cbor_items->ead_3, cbor_items->ead_3_len,
				      &ead_tokens, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		cbor_items->ead_3_len = len;
	}

	const size_t encoded_bytes =
		cbor_items->id_cred_i_len + cbor_items->th_3_len +
		cbor_items->cred_i_len + cbor_items->ead_3_len;

	if (encoded_bytes > cbor_items->buf_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	cbor_items->buf_len = encoded_bytes;
	return EDHOC_SUCCESS;
}

static int calc_mac_3(const struct edhoc_context *ctx,
		      const struct cbor_items *cbor_items, uint8_t *mac_3,
		      size_t mac_3_len)
{
	if (NULL == ctx || NULL == cbor_items || NULL == mac_3 ||
	    0 == mac_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_4E3M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_3,
		._info_context.value = cbor_items->buf,
		._info_context.len = cbor_items->buf_len,
		._info_length = mac_3_len,
	};

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += cbor_int_overhead(EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_3);
	len += cbor_items->buf_len + cbor_bstr_overhead(cbor_items->buf_len);
	len += cbor_int_overhead(mac_3_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	LOG("MAC_3 info", info, len);

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys_cb.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
					key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto_cb.expand(key_id, info, len, mac_3, mac_3_len);
	ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_sign_or_mac_3(const struct edhoc_context *ctx,
				 const struct edhoc_auth_creds *auth_creds,
				 const struct cbor_items *cbor_items,
				 const uint8_t *mac_3, size_t mac_3_len,
				 uint8_t *sign, size_t sign_len)
{
	if (NULL == ctx || NULL == auth_creds || NULL == cbor_items ||
	    NULL == mac_3 || 0 == mac_3_len || NULL == sign || 0 == sign_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct sig_structure cose_sign_1 = {
		._sig_structure_protected.value = cbor_items->id_cred_i,
		._sig_structure_protected.len = cbor_items->id_cred_i_len,
		._sig_structure_external_aad.value = cbor_items->th_3,
		._sig_structure_external_aad.len = cbor_items->th_3_len +
						   cbor_items->cred_i_len +
						   cbor_items->ead_3_len,
		._sig_structure_payload.value = mac_3,
		._sig_structure_payload.len = mac_3_len,
	};

	size_t len = 0;
	len += sizeof("Signature1") + cbor_tstr_overhead(sizeof("Signature1"));
	len += cbor_items->id_cred_i_len +
	       cbor_bstr_overhead(cbor_items->id_cred_i_len);
	len += cbor_items->th_3_len + cbor_items->cred_i_len +
	       cbor_items->ead_3_len +
	       cbor_bstr_overhead(cbor_items->th_3_len +
				  cbor_items->cred_i_len +
				  cbor_items->ead_3_len);
	len += mac_3_len + cbor_bstr_overhead(mac_3_len);

	uint8_t cose_sign_1_buf[len];
	memset(cose_sign_1_buf, 0, sizeof(cose_sign_1_buf));

	len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					ARRAY_SIZE(cose_sign_1_buf),
					&cose_sign_1, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	const size_t cose_sign_1_buf_len = len;

	len = 0;
	ret = ctx->crypto_cb.sign(auth_creds->priv_key_id, cose_sign_1_buf,
				  cose_sign_1_buf_len, sign, sign_len, &len);

	if (EDHOC_SUCCESS != ret || sign_len != len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int prepare_plaintext_3(const struct cbor_items *cbor_items,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t offset = 0;

	/* ID_CRED_I. */
	if (cbor_items->id_cred_i_is_cob) {
		memcpy(ptxt, &cbor_items->id_cred_i_cob_val,
		       (size_t)cbor_items->id_cred_i_is_cob);
		offset += (size_t)cbor_items->id_cred_i_is_cob;
	} else {
		memcpy(ptxt, cbor_items->id_cred_i, cbor_items->id_cred_i_len);
		offset += cbor_items->id_cred_i_len;
	}

	const struct zcbor_string cbor_sign_or_mac_3 = {
		.value = sign,
		.len = sign_len,
	};

	size_t len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&ptxt[offset], sign_len + cbor_bstr_overhead(sign_len),
		&cbor_sign_or_mac_3, &len);

	if (ZCBOR_SUCCESS != ret ||
	    (sign_len + cbor_bstr_overhead(sign_len)) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len;

	/* EAD_3 if present. */
	if (cbor_items->is_ead_3) {
		memcpy(&ptxt[offset], cbor_items->ead_3, cbor_items->ead_3_len);
		offset += cbor_items->ead_3_len;
	}

	if (offset > ptxt_size)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	return EDHOC_SUCCESS;
}

static size_t compute_aad_3_len(const struct edhoc_context *ctx)
{
	size_t len = 0;

	len += sizeof("Encrypt0") + cbor_tstr_overhead(sizeof("Encrypt0"));
	len += 0 + cbor_bstr_overhead(0);
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);

	return len;
}

static int compute_key_iv_aad(const struct edhoc_context *ctx, uint8_t *key,
			      size_t key_len, uint8_t *iv, size_t iv_len,
			      uint8_t *aad, size_t aad_len)
{
	if (NULL == ctx || NULL == key || 0 == key_len || NULL == iv ||
	    0 == iv_len || NULL == aad || 0 == aad_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_3 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	struct info input_info = { 0 };

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += cbor_int_overhead(EDHOC_EXTRACT_PRK_INFO_LABEL_IV);
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += cbor_int_overhead(csuite.aead_key_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	/* Generate K_3. */
	input_info = (struct info){
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_KEY,
		._info_context.value = ctx->th,
		._info_context.len = ctx->th_len,
		._info_length = csuite.aead_key_len,
	};

	memset(info, 0, sizeof(info));
	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->keys_cb.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
					key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto_cb.expand(key_id, info, len, key, key_len);
	ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* Generate IV_3. */
	input_info = (struct info){
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_IV,
		._info_context.value = ctx->th,
		._info_context.len = ctx->th_len,
		._info_length = csuite.aead_iv_len,
	};

	memset(info, 0, sizeof(info));
	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->keys_cb.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
					key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto_cb.expand(key_id, info, len, iv, iv_len);
	ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* Generate AAD_3. */
	struct enc_structure cose_enc_0 = {
		._enc_structure_protected.value = NULL,
		._enc_structure_protected.len = 0,
		._enc_structure_external_aad.value = ctx->th,
		._enc_structure_external_aad.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_enc_structure(aad, aad_len, &cose_enc_0, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ptxt, size_t ptxt_len,
			      uint8_t *ctxt, size_t ctxt_size, size_t *ctxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys_cb.generate_key(EDHOC_KT_ENCRYPT, key, key_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto_cb.encrypt(key_id, iv, iv_len, aad, aad_len, ptxt,
				     ptxt_len, ctxt, ctxt_size, ctxt_len);
	ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_th_4(struct edhoc_context *ctx,
			const struct cbor_items *cbor_items,
			const uint8_t *ptxt, size_t ptxt_len)
{
	if (NULL == ctx || NULL == cbor_items || NULL == ptxt || 0 == ptxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_3 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;
	size_t offset = 0;

	/* Calculate required buffer length for TH_4. */
	len = 0;
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += ptxt_len;
	len += cbor_items->cred_i_len;

	uint8_t th_4[len];
	memset(th_4, 0, sizeof(th_4));

	/* TH_3. */
	const struct zcbor_string cbor_th_3 = {
		.value = ctx->th,
		.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&th_4[offset], ARRAY_SIZE(th_4), &cbor_th_3, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len;

	/* PLAINTEXT_3. */
	memcpy(&th_4[offset], ptxt, ptxt_len);
	offset += ptxt_len;

	/* CRED_I. */
	memcpy(&th_4[offset], cbor_items->cred_i, cbor_items->cred_i_len);
	offset += cbor_items->cred_i_len;

	if (ARRAY_SIZE(th_4) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	/* Calculate TH_4. */
	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_len;

	size_t hash_length = 0;
	ret = ctx->crypto_cb.hash(th_4, ARRAY_SIZE(th_4), ctx->th, ctx->th_len,
				  &hash_length);

	if (EDHOC_SUCCESS != ret || ctx->th_len != hash_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_4;
	return EDHOC_SUCCESS;
}

static int compute_prk_out(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += cbor_int_overhead(EDHOC_EXTRACT_PRK_INFO_LABEL_IV);
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += cbor_int_overhead(csuite.hash_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	/* Generate PRK_out. */
	struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_OUT,
		._info_context.value = ctx->th,
		._info_context.len = ctx->th_len,
		._info_length = csuite.hash_len,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys_cb.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
					key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto_cb.expand(key_id, info, len, ctx->prk, ctx->prk_len);
	ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->prk_state = EDHOC_PRK_STATE_OUT;
	return EDHOC_SUCCESS;
}

static int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
		     size_t msg_3_size, size_t *msg_3_len)
{
	if (NULL == ctxt || 0 == ctxt_len || NULL == msg_3 || 0 == msg_3_size)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct zcbor_string input_bstr = {
		.value = ctxt,
		.len = ctxt_len,
	};

	ret = cbor_encode_message_3_CIPHERTEXT_3(msg_3, msg_3_size, &input_bstr,
						 msg_3_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len)
{
	if (NULL == msg_3 || 0 == msg_3_len || NULL == ctxt_3 ||
	    NULL == ctxt_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	struct zcbor_string dec_msg_3 = { 0 };
	ret = cbor_decode_message_3_CIPHERTEXT_3(msg_3, msg_3_len, &dec_msg_3,
						 &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	*ctxt_3 = dec_msg_3.value;
	*ctxt_3_len = dec_msg_3.len;

	return EDHOC_SUCCESS;
}

static int decrypt_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ctxt, size_t ctxt_len,
			      uint8_t *ptxt, size_t ptxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys_cb.generate_key(EDHOC_KT_DECRYPT, key, key_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	size_t len = 0;
	ret = ctx->crypto_cb.decrypt(key_id, iv, iv_len, aad, aad_len, ctxt,
				     ctxt_len, ptxt, ptxt_len, &len);
	ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret || ptxt_len != len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt)
{
	if (NULL == ctx || NULL == ptxt || 0 == ptxt_len || NULL == parsed_ptxt)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_x cbor_ptxt_3 = { 0 };
	ret = cbor_decode_plaintext_x(ptxt, ptxt_len, &cbor_ptxt_3, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* ID_CRED_I */
	switch (cbor_ptxt_3._plaintext_x_ID_CRED_choice) {
	case _plaintext_x_ID_CRED_int: {
		parsed_ptxt->auth_creds.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_creds.key_id.key_id_len = 1;
		parsed_ptxt->auth_creds.key_id.key_id[0] =
			(int8_t)cbor_ptxt_3._plaintext_x_ID_CRED_int;
		break;
	}

	case _plaintext_x_ID_CRED_bstr:
		return EDHOC_ERROR_NOT_SUPPORTED;

	case _plaintext_x_ID_CRED__map: {
		const struct map *cbor_map =
			&cbor_ptxt_3._plaintext_x_ID_CRED__map;

		if (cbor_map->_map_x5chain_present) {
			parsed_ptxt->auth_creds.label =
				EDHOC_COSE_HEADER_X509_CHAIN;
			parsed_ptxt->auth_creds.x509_chain.cert =
				cbor_map->_map_x5chain._map_x5chain.value;
			parsed_ptxt->auth_creds.x509_chain.cert_len =
				cbor_map->_map_x5chain._map_x5chain.len;
			break;
		}

		if (cbor_map->_map_x5t_present) {
			parsed_ptxt->auth_creds.label =
				EDHOC_COSE_HEADER_X509_HASH;
			parsed_ptxt->auth_creds.x509_hash.cert_fp =
				cbor_map->_map_x5t._map_x5t_hash.value;
			parsed_ptxt->auth_creds.x509_hash.cert_fp_len =
				cbor_map->_map_x5t._map_x5t_hash.len;

			if (_map_x5t_alg_int ==
				    cbor_map->_map_x5t._map_x5t_alg_choice &&
			    ONE_BYTE_CBOR_INT_MIN_VALUE <
				    cbor_map->_map_x5t._map_x5t_alg_int &&
			    ONE_BYTE_CBOR_INT_MAX_VALUE >
				    cbor_map->_map_x5t._map_x5t_alg_int) {
				parsed_ptxt->auth_creds.x509_hash.alg_len = 1;
				parsed_ptxt->auth_creds.x509_hash.alg[0] =
					(int8_t)cbor_map->_map_x5t
						._map_x5t_alg_int;
			} else {
				parsed_ptxt->auth_creds.x509_hash.alg_len =
					cbor_map->_map_x5t._map_x5t_alg_bstr.len;
				memcpy(parsed_ptxt->auth_creds.x509_hash.alg,
				       cbor_map->_map_x5t._map_x5t_alg_bstr
					       .value,
				       parsed_ptxt->auth_creds.x509_hash
					       .alg_len);
			}
			break;
		}
	}
	}

	/* Sign_or_MAC_3 */
	parsed_ptxt->sign_or_mac =
		cbor_ptxt_3._plaintext_x_Signature_or_MAC.value;
	parsed_ptxt->sign_or_mac_len =
		cbor_ptxt_3._plaintext_x_Signature_or_MAC.len;

	/* EAD_3 if present */
	if (cbor_ptxt_3._plaintext_x_EAD_present) {
		ctx->nr_of_ead_tokens =
			cbor_ptxt_3._plaintext_x_EAD._ead_x_count;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				cbor_ptxt_3._plaintext_x_EAD._ead_x[i]
					._ead_x_ead_label;
			ctx->ead_token[i].value =
				cbor_ptxt_3._plaintext_x_EAD._ead_x[i]
					._ead_x_ead_value.value;
			ctx->ead_token[i].value_len =
				cbor_ptxt_3._plaintext_x_EAD._ead_x[i]
					._ead_x_ead_value.len;
		}
	}

	return EDHOC_SUCCESS;
}

static int verify_sign_or_mac_3(const struct edhoc_context *ctx,
				const struct cbor_items *cbor_items,
				const struct plaintext *parsed_ptxt,
				const uint8_t *pub_key, size_t pub_key_len,
				const uint8_t *mac_3, size_t mac_3_len)
{
	if (NULL == ctx || NULL == cbor_items || NULL == parsed_ptxt ||
	    NULL == pub_key || 0 == pub_key_len || NULL == mac_3 ||
	    0 == mac_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	const struct sig_structure cose_sign_1 = {
		._sig_structure_protected.value = cbor_items->id_cred_i,
		._sig_structure_protected.len = cbor_items->id_cred_i_len,
		._sig_structure_external_aad.value = cbor_items->th_3,
		._sig_structure_external_aad.len = cbor_items->th_3_len +
						   cbor_items->cred_i_len +
						   cbor_items->ead_3_len,
		._sig_structure_payload.value = mac_3,
		._sig_structure_payload.len = mac_3_len,
	};

	len = 0;
	len += sizeof("Signature1") + cbor_tstr_overhead(sizeof("Signature1"));
	len += cbor_items->id_cred_i_len +
	       cbor_bstr_overhead(cbor_items->id_cred_i_len);
	len += cbor_items->th_3_len + cbor_items->cred_i_len +
	       cbor_items->ead_3_len +
	       cbor_bstr_overhead(cbor_items->th_3_len +
				  cbor_items->cred_i_len +
				  cbor_items->ead_3_len);
	len += mac_3_len + cbor_bstr_overhead(mac_3_len);

	uint8_t cose_sign_1_buf[len];
	memset(cose_sign_1_buf, 0, sizeof(cose_sign_1_buf));

	len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					ARRAY_SIZE(cose_sign_1_buf),
					&cose_sign_1, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys_cb.generate_key(EDHOC_KT_VERIFY, pub_key, pub_key_len,
					key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto_cb.verify(key_id, cose_sign_1_buf, len,
				    parsed_ptxt->sign_or_mac,
				    parsed_ptxt->sign_or_mac_len);
	ctx->keys_cb.destroy_key(key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 3:
 *      1.  Choose most preferred cipher suite.
 *      2.  Compose EAD_3 if present.
 *      3.  Fetch authentication credentials.
 *      4.  Compute PRK_4e3m.
 *      5a. Compute required buffer length for context_3.
 *      5b. Cborise items required by context_3.
 *      5c. Compute Message Authentication Code (MAC_3).
 *      6.  Compute signature if needed (Signature_or_MAC_3).
 *      7.  Prepare plaintext (PLAINTEXT_3).
 *      8.  Compute K_3, IV_3 and AAD_3.
 *      9.  Compute ciphertext.
 *      10. Compute transcript hash 4.
 *      11. Compute output psuedo random key (PRK_out).
 *      12. Generate edhoc message 3.
 */
int edhoc_message_3_compose(struct edhoc_context *ctx, uint8_t *msg_3,
			    size_t msg_3_size, size_t *msg_3_len)
{
	if (NULL == ctx || VERIFIED_M2 != ctx->status || NULL == msg_3 ||
	    0 == msg_3_size || NULL == msg_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (VERIFIED_M2 != ctx->status || EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_PRK_STATE_4E3M != ctx->prk_state;

	ctx->status = ABORTED;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Compose EAD_3 if present. */
	if (NULL != ctx->ead_compose && 0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->ead_compose(ctx->user_ctx, EDHOC_MSG_3,
				       ctx->ead_token,
				       ARRAY_SIZE(ctx->ead_token) - 1,
				       &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens)
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	/* 3. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_creds = { 0 };
	ret = ctx->creds_cb.fetch(ctx->user_ctx, &auth_creds);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/* 4. Compute PRK_4e3m. */
	ret = compute_prk_4e3m(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* 5a. Compute required buffer length for context_3. */
	const size_t context_3_len = calc_mac_3_input_len(ctx, &auth_creds);

	if (0 == context_3_len)
		return EDHOC_ERROR_INVALID_MAC_3;

	uint8_t mac_3_content[sizeof(struct cbor_items) + context_3_len];
	memset(mac_3_content, 0, sizeof(mac_3_content));

	struct cbor_items *cbor_items = (struct cbor_items *)mac_3_content;
	cbor_items->buf_len = context_3_len;

	/* 5b. Cborise items required by context_3. */
	ret = calc_mac_3_context(ctx, &auth_creds, cbor_items);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	LOG("context_3", cbor_items->buf, cbor_items->buf_len);

	/* 5c. Compute Message Authentication Code (MAC_3). */
	uint8_t mac_3[csuite.hash_len];
	memset(mac_3, 0, sizeof(mac_3));

	ret = calc_mac_3(ctx, cbor_items, mac_3, ARRAY_SIZE(mac_3));

	if (EDHOC_SUCCESS != ret) {
		ctx->status = ABORTED;
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	LOG("MAC_3", mac_3, ARRAY_SIZE(mac_3));

	/* 6. Compute signature if needed (Signature_or_MAC_3). */
	uint8_t sign[csuite.ecc_sign_len];
	memset(sign, 0, sizeof(sign));

	switch (ctx->method) {
	case EDHOC_INIT_SIGN_RESP_SIGN:
		ret = compute_sign_or_mac_3(ctx, &auth_creds, cbor_items, mac_3,
					    ARRAY_SIZE(mac_3), sign,
					    ARRAY_SIZE(sign));
		break;

	case EDHOC_INIT_STAT_RESP_SIGN:
	case EDHOC_INIT_SIGN_RESP_STAT:
	case EDHOC_INIT_STAT_RESP_STAT:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_3;

	LOG("Signature_or_MAC_3", sign, ARRAY_SIZE(sign));

	/* 7. Prepare plaintext (PLAINTEXT_3). */
	size_t plaintext_len = 0;
	plaintext_len +=
		(cbor_items->id_cred_i_is_cob) ? 1 : cbor_items->id_cred_i_len;
	plaintext_len += ARRAY_SIZE(sign);
	plaintext_len += cbor_bstr_overhead(ARRAY_SIZE(sign));
	plaintext_len += cbor_items->ead_3_len;

	uint8_t plaintext[plaintext_len];
	memset(plaintext, 0, sizeof(plaintext));

	ret = prepare_plaintext_3(cbor_items, sign, ARRAY_SIZE(sign), plaintext,
				  ARRAY_SIZE(plaintext));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	LOG("PLAINTEXT_3", plaintext, ARRAY_SIZE(plaintext));

	/* 8. Compute K_3, IV_3 and AAD_3. */
	uint8_t key[csuite.aead_key_len];
	memset(key, 0, sizeof(key));

	uint8_t iv[csuite.aead_iv_len];
	memset(iv, 0, sizeof(iv));

	const size_t aad_len = compute_aad_3_len(ctx);
	uint8_t aad[aad_len];
	memset(aad, 0, sizeof(aad));

	ret = compute_key_iv_aad(ctx, key, ARRAY_SIZE(key), iv, ARRAY_SIZE(iv),
				 aad, ARRAY_SIZE(aad));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	LOG("K_3", key, ARRAY_SIZE(key));
	LOG("IV_3", iv, ARRAY_SIZE(iv));
	LOG("AAD_3", aad, ARRAY_SIZE(aad));

	/* 9. Compute ciphertext. */
	size_t ciphertext_len = 0;
	uint8_t ciphertext[ARRAY_SIZE(plaintext) + csuite.aead_tag_len];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = compute_ciphertext(ctx, key, ARRAY_SIZE(key), iv, ARRAY_SIZE(iv),
				 aad, ARRAY_SIZE(aad), plaintext,
				 ARRAY_SIZE(plaintext), ciphertext,
				 ARRAY_SIZE(ciphertext), &ciphertext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	LOG("CIPHERTEXT_3", ciphertext, ciphertext_len);

	/* 10. Compute transcript hash 4. */
	ret = compute_th_4(ctx, cbor_items, plaintext, ARRAY_SIZE(plaintext));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	/* 11. Compute output psuedo random key (PRK_out). */
	ret = compute_prk_out(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	/* 12. Generate edhoc message 3. */
	ret = gen_msg_3(ciphertext, ciphertext_len, msg_3, msg_3_size,
			msg_3_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = COMPLETED;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 3:
 *      1.  Choose most preferred cipher suite.
 *      2.  CBOR decode message 3.
 *      3.  Compute K_3, IV_3 and AAD_3.
 *      4.  Decrypt ciphertext.
 *      5.  Parse CBOR plaintext (PLAINTEXT_3).
 *      6.  Process EAD_3 if present.
 *      7.  Verify if credentials from peer are trusted.
 *      8.  Compute PRK_4e3m.
 *      9a. Compute required buffer length for context_3.
 *      9b. Cborise items required by context_3.
 *      9c. Compute Message Authentication Code (MAC_3).
 *      10. Verify Signature_or_MAC_3.
 *      11. Compute transcript hash 4.
 *      12. Compute output psuedo random key (PRK_out).
 */
int edhoc_message_3_process(struct edhoc_context *ctx, const uint8_t *msg_3,
			    size_t msg_3_len)
{
	if (NULL == ctx || NULL == msg_3 || 0 == msg_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (WAIT_M3 != ctx->status || EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = ABORTED;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. CBOR decode message 3. */
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	ret = parse_msg_3(msg_3, msg_3_len, &ctxt, &ctxt_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;

	/* 3. Compute K_3, IV_3 and AAD_3. */
	uint8_t key[csuite.aead_key_len];
	memset(key, 0, sizeof(key));

	uint8_t iv[csuite.aead_iv_len];
	memset(iv, 0, sizeof(iv));

	const size_t aad_len = compute_aad_3_len(ctx);
	uint8_t aad[aad_len];
	memset(aad, 0, sizeof(aad));

	ret = compute_key_iv_aad(ctx, key, ARRAY_SIZE(key), iv, ARRAY_SIZE(iv),
				 aad, ARRAY_SIZE(aad));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	LOG("K_3", key, ARRAY_SIZE(key));
	LOG("IV_3", iv, ARRAY_SIZE(iv));
	LOG("AAD_3", aad, ARRAY_SIZE(aad));

	/* 4. Decrypt ciphertext. */
	uint8_t ptxt[ctxt_len - csuite.aead_tag_len];
	memset(ptxt, 0, sizeof(ptxt));

	ret = decrypt_ciphertext(ctx, key, ARRAY_SIZE(key), iv, ARRAY_SIZE(iv),
				 aad, ARRAY_SIZE(aad), ctxt, ctxt_len, ptxt,
				 ARRAY_SIZE(ptxt));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	LOG("PLAINTEXT_3", ptxt, ARRAY_SIZE(ptxt));

	/* 5. Parse CBOR plaintext (PLAINTEXT_3). */
	struct plaintext parsed_ptxt = { 0 };
	ret = parse_plaintext(ctx, ptxt, ARRAY_SIZE(ptxt), &parsed_ptxt);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* 6. Process EAD_3 if present. */
	if (NULL != ctx->ead_process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead_process(ctx->user_ctx, EDHOC_MSG_3,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	/* 7. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;
	ret = ctx->creds_cb.verify(ctx->user_ctx, &parsed_ptxt.auth_creds,
				   &pub_key, &pub_key_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/* 8. Compute PRK_4e3m. */
	ret = compute_prk_4e3m(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* 9a. Compute required buffer length for context_3. */
	const size_t context_3_len =
		calc_mac_3_input_len(ctx, &parsed_ptxt.auth_creds);

	if (0 == context_3_len)
		return EDHOC_ERROR_INVALID_MAC_3;

	uint8_t mac_3_content[sizeof(struct cbor_items) + context_3_len];
	memset(mac_3_content, 0, sizeof(mac_3_content));

	struct cbor_items *cbor_items = (struct cbor_items *)mac_3_content;
	cbor_items->buf_len = context_3_len;

	/* 9b. Cborise items required by context_3. */
	ret = calc_mac_3_context(ctx, &parsed_ptxt.auth_creds, cbor_items);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	LOG("context_3", cbor_items->buf, cbor_items->buf_len);

	/* 9c. Compute Message Authentication Code (MAC_3). */
	uint8_t mac_3[csuite.hash_len];
	memset(mac_3, 0, sizeof(mac_3));

	ret = calc_mac_3(ctx, cbor_items, mac_3, ARRAY_SIZE(mac_3));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	LOG("MAC_3", mac_3, ARRAY_SIZE(mac_3));

	/* 10. Verify Signature_or_MAC_3. */
	ret = verify_sign_or_mac_3(ctx, cbor_items, &parsed_ptxt, pub_key,
				   pub_key_len, mac_3, ARRAY_SIZE(mac_3));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_3;

	/* 11. Compute transcript hash 4. */
	ret = compute_th_4(ctx, cbor_items, ptxt, ARRAY_SIZE(ptxt));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	/* 12. Compute output psuedo random key (PRK_out). */
	ret = compute_prk_out(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = COMPLETED;
	return EDHOC_SUCCESS;
}