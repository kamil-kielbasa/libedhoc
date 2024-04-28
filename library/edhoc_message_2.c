/**
 * \file    edhoc_message_2.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 2.
 * \version 0.2
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include <zcbor_common.h>
#include <backend_cbor_message_2_encode.h>
#include <backend_cbor_message_2_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_bstr_type_decode.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_int_type_decode.h>
#include <backend_cbor_id_cred_x_encode.h>
#include <backend_cbor_id_cred_x_decode.h>
#include <backend_cbor_sig_structure_encode.h>
#include <backend_cbor_info_encode.h>
#include <backend_cbor_plaintext_2_decode.h>
#include <backend_cbor_ead_encode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/**
 * \brief Helper structure for CBOR encoding. 
 */
struct cbor_items {
	uint8_t *conn_id;
	size_t conn_id_len;

	bool id_cred_r_is_cob; // cob = cbor one byte
	int32_t id_cred_r_cob_val; // cob = cbor one byte
	uint8_t *id_cred_r;
	size_t id_cred_r_len;

	uint8_t *th_2;
	size_t th_2_len;

	uint8_t *cred_r;
	size_t cred_r_len;

	bool is_ead_2;
	uint8_t *ead_2;
	size_t ead_2_len;

	size_t buf_len;
	uint8_t buf[];
};

/**
 * \brief Helper structure for parsed PLAINTEXT_2.
 */
struct plaintext {
	struct edhoc_auth_creds auth_cred;

	const uint8_t *sign_or_mac;
	size_t sign_or_mac_len;

	const uint8_t *ead;
	size_t ead_len;
};

/**
 * \brief Processing side.
 */
enum edhoc_role {
	initiator,
	responder,
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** 
 * \brief CBOR integer memory requirements.
 *
 * \param val                   Raw integer value.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_int_mem_req(int32_t val);

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
 * \param len                   Length of buffer to CBOR as bstr.
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
 * \param val                   Value for cbor encoding.
 *
 * \retval True if might be encoded as one byte cbor integer,
 *         otherwise false.
 */
static inline bool is_cbor_one_byte_int(int32_t val);

/** 
 * \brief Generate ECDH key pair (G_X, X).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int gen_dh_keys(struct edhoc_context *ctx);

/** 
 * \brief Calculate ECDH shared secret (G_XY).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int calc_dh_secret(struct edhoc_context *ctx);

/** 
 * \brief Calculate transcript hash 2 (TH_2).
 *
 * \param[in,out] ctx		EDHOC context.
 * \param role                  EDHOC role.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int calc_th_2(struct edhoc_context *ctx, enum edhoc_role role);

/** 
 * \brief Compute psuedo random key (PRK_2e).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int compute_prk_2e(struct edhoc_context *ctx);

/** 
 * \brief Compute psuedo random key (PRK_3e2m).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_prk_3e2m(struct edhoc_context *ctx);

/** 
 * \brief Calculate memory required for input (context_2) for for MAC_2.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param role                  EDHOC role.
 *
 * \return Value different than 0 on success, otherwise failure.
 */
static size_t calc_mac_2_input_len(const struct edhoc_context *ctx,
				   const struct edhoc_auth_creds *auth_cred,
				   enum edhoc_role role);

/** 
 * \brief Generate context_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param role                  EDHOC role.
 * \param[out] cbor_items	Buffer where the generated context_2 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int calc_mac_2_context(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_cred,
			      enum edhoc_role role,
			      struct cbor_items *cbor_items);

/** 
 * \brief Compute MAC_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] cbor_items	Buffer containing the context_2.
 * \param[out] mac_2		Buffer where the generated MAC_2 is to be written.
 * \param mac_2_len		Size of the \p mac_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int calc_mac_2(const struct edhoc_context *ctx,
		      const struct cbor_items *cbor_items, uint8_t *mac_2,
		      size_t mac_2_len);

/** 
 * \brief Compute Signature_or_MAC_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] auth_cred	        Authentication credentials.
 * \param[in] cbor_items	Buffer containing the context_2.
 * \param[in] mac_2		Buffer containing the MAC_2.
 * \param mac_2_len		Size of the \p mac_2 buffer in bytes.
 * \param[out] sign		Buffer where the generated signature is to be written.
 * \param sign_len		Size of the \p sign buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int calc_sign_or_mac_2(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_cred,
			      const struct cbor_items *cbor_items,
			      const uint8_t *mac_2, size_t mac_2_len,
			      uint8_t *sign, size_t sign_len);

/** 
 * \brief Prepare PLAINTEXT_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] cbor_items	Buffer containing the context_2.
 * \param[in] sign		Buffer containing the signature.
 * \param sign_len		Size of the \p sign buffer in bytes.
 * \param[out] ptxt	        Buffer where the generated plaintext is to be written.
 * \param ptxt_len		Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct cbor_items *cbor_items,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_len);

/** 
 * \brief Compute KEYSTREAM_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] prk_2e		Buffer containing the PRK_2e.
 * \param prk_2e_len		Size of the \p prk_2e buffer in bytes.
 * \param[out] keystream	Buffer where the generated keystream is to be written.
 * \param keystream_len		Size of the \p keystream buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_keystream(const struct edhoc_context *ctx,
			     const uint8_t *prk_2e, size_t prk_2e_len,
			     uint8_t *keystream, size_t keystream_len);

/** 
 * \brief Compute CIPHERTEXT_2.
 *
 * \param[out] dst		Memory location to XOR to.
 * \param[in] src		Memory location to XOR from.
 * \param count			Number of bytes to XOR.
 */
static void xor_arrays(uint8_t *restrict dst, const uint8_t *restrict src,
		       size_t count);

/** 
 * \brief Prepare MESSAGE_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ciphertext	Buffer containing the CIPHERTEXT_2.
 * \param ciphertext_len	Size of the \p ciphertext buffer in bytes.
 * \param[out] msg_2        	Buffer where the generated message 2 is to be written.
 * \param msg_2_size        	Size of the \p msg_2 buffer in bytes.
 * \param[out] msg_2_len	On success, the number of bytes that make up the message 2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ciphertext, size_t ciphertext_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len);

/** 
 * \brief Get from cborised message 2 length of ciphertext 2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message 2.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[out] len		Length of ciphertext 2 in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_ciphertext_2_len(const struct edhoc_context *ctx,
				    const uint8_t *msg_2, size_t msg_2_len,
				    size_t *len);

/** 
 * \brief Decode message 2 and save into context and buffer.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message 2.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[in] ctxt_2	        Buffer containing the CIPHERTEXT_2.
 * \param ctxt_2_len	        Size of the \p ctxt_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len);

/** 
 * \brief Parsed cborised PLAINTEXT_2 for separate buffers.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] plaintext		Buffer containing the PLAINTEXT_2.
 * \param plaintext_len         Size of the \p plaintext buffer in bytes.
 * \param[out] ptxt     	Structure where parsed PLAINTEXT_2 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt);

/** 
 * \brief Verify Signature_or_MAC_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] cbor_items        Structure containing the context_2.
 * \param[in] parsed_ptxt     	Structure containing the parsed PLAINTEXT_2.
 * \param[in] pub_key           Buffer containing the public key from peer credentials.
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 * \param[in] mac_2             Buffer containing the MAC_2.
 * \param mac_2_len             Size of the \p mac_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int verify_sign_or_mac_2(const struct edhoc_context *ctx,
				const struct cbor_items *cbor_items,
				const struct plaintext *parsed_ptxt,
				const uint8_t *pub_key, size_t pub_key_len,
				const uint8_t *mac_2, size_t mac_2_len);

/** 
 * \brief Calculate transcript hash 3.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] cbor_items        Structure containing the context_2.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_2.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int calc_th_3(struct edhoc_context *ctx,
		     const struct cbor_items *cbor_items, const uint8_t *ptxt,
		     size_t ptxt_len);

/* Static function definitions --------------------------------------------- */

static inline size_t cbor_int_mem_req(int32_t val)
{
	if (val >= ONE_BYTE_CBOR_INT_MIN_VALUE &&
	    val <= ONE_BYTE_CBOR_INT_MAX_VALUE) {
		return 1;
	} else if (val >= -(UINT8_MAX + 1) && val <= UINT8_MAX) {
		return 2;
	} else if (val >= -(UINT16_MAX + 1) && val <= UINT16_MAX) {
		return 3;
	} else {
		return 4;
	}
}

static inline size_t cbor_tstr_overhead(size_t len)
{
	if (len <= 23) {
		return 1;
	} else if (len <= UINT8_MAX) {
		return 2;
	} else if (len <= UINT16_MAX) {
		return 3;
	} else if (len <= UINT32_MAX) {
		return 4;
	} else {
		return 5;
	}
}

static inline size_t cbor_bstr_overhead(size_t len)
{
	if (len <= 23) {
		return 1;
	} else if (len <= UINT8_MAX) {
		return 2;
	} else if (len <= UINT16_MAX) {
		return 3;
	} else if (len <= UINT32_MAX) {
		return 4;
	} else {
		return 5;
	}
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

static inline bool is_cbor_one_byte_int(int32_t val)
{
	return 1 == cbor_int_mem_req(val);
}

static int gen_dh_keys(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* Generate ephemeral key pair. */
	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_MAKE_KEY_PAIR, NULL, 0, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	ctx->dh_pub_key_len = csuite.ecc_key_length;
	ctx->dh_priv_key_len = csuite.ecc_key_length;

	size_t pub_key_len = 0;
	size_t priv_key_len = 0;
	ret = ctx->crypto.make_key_pair(key_id, ctx->dh_priv_key,
					ctx->dh_priv_key_len, &priv_key_len,
					ctx->dh_pub_key, ctx->dh_pub_key_len,
					&pub_key_len);
	ctx->keys.destroy_key(key_id);

	if (EDHOC_SUCCESS != ret || csuite.ecc_key_length != priv_key_len ||
	    csuite.ecc_key_length != pub_key_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int calc_dh_secret(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_KEY_AGREEMENT, ctx->dh_priv_key,
				     ctx->dh_priv_key_len, key_id);
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];
	ctx->dh_secret_len = csuite.ecc_key_length;

	size_t secret_len = 0;
	ret = ctx->crypto.key_agreement(key_id, ctx->dh_peer_pub_key,
					ctx->dh_peer_pub_key_len,
					ctx->dh_secret, ctx->dh_secret_len,
					&secret_len);
	ctx->keys.destroy_key(key_id);
	memset(ctx->dh_priv_key, 0, sizeof(ctx->dh_priv_key));

	if (EDHOC_SUCCESS != ret || secret_len != csuite.ecc_key_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int calc_th_2(struct edhoc_context *ctx, enum edhoc_role role)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_1 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* Calculate required sizes for CBOR TH_2 = H(G_Y, H(message_1)). */
	size_t g_y_len = 0;
	g_y_len += csuite.ecc_key_length;
	g_y_len += cbor_bstr_overhead(csuite.ecc_key_length);

	size_t hash_len = 0;
	hash_len += csuite.hash_length;
	hash_len += cbor_bstr_overhead(csuite.hash_length);

	uint8_t th_2[g_y_len + hash_len];
	memset(th_2, 0, sizeof(th_2));

	size_t offset = 0;
	size_t len_out = 0;
	struct zcbor_string cbor_bstr = { 0 };

	/* Cborise G_Y. */
	switch (role) {
	case initiator:
		cbor_bstr.value = ctx->dh_peer_pub_key;
		cbor_bstr.len = ctx->dh_peer_pub_key_len;
		break;
	case responder:
		cbor_bstr.value = ctx->dh_pub_key;
		cbor_bstr.len = ctx->dh_pub_key_len;
		break;
	}

	len_out = 0;
	ret = cbor_encode_byte_string_type_bstr_type(th_2, g_y_len, &cbor_bstr,
						     &len_out);

	if (ZCBOR_SUCCESS != ret || g_y_len != len_out)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len_out;

	/* Cborise H(message_1). */
	cbor_bstr.value = ctx->th;
	cbor_bstr.len = ctx->th_len;

	len_out = 0;
	ret = cbor_encode_byte_string_type_bstr_type(&th_2[offset], hash_len,
						     &cbor_bstr, &len_out);

	if (ZCBOR_SUCCESS != ret || hash_len != len_out)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len_out;

	if (ARRAY_SIZE(th_2) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	/* Calculate TH_2. */
	ctx->th_len = csuite.hash_length;

	size_t hash_length = 0;
	ret = ctx->crypto.hash(th_2, ARRAY_SIZE(th_2), ctx->th, ctx->th_len,
			       &hash_length);

	if (EDHOC_SUCCESS != ret || csuite.hash_length != hash_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_2;
	return EDHOC_SUCCESS;
}

static int compute_prk_2e(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (ctx->method) {
	case EDHOC_METHOD_0: {
		ctx->prk_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		uint8_t key_id[EDHOC_KID_LEN] = { 0 };
		ret = ctx->keys.generate_key(EDHOC_KT_EXTRACT, ctx->dh_secret,
					     ctx->dh_secret_len, key_id);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		size_t out_len = 0;
		ret = ctx->crypto.extract(key_id, ctx->th, ctx->th_len,
					  ctx->prk, ctx->prk_len, &out_len);
		ctx->keys.destroy_key(key_id);

		if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		ctx->prk_state = EDHOC_PRK_STATE_2E;
		return EDHOC_SUCCESS;
	}

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_2:
	case EDHOC_METHOD_3:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_ERROR_GENERIC_ERROR;
}

static int compute_prk_3e2m(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_2E != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	switch (ctx->method) {
	case EDHOC_METHOD_0:
		ctx->prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_2:
	case EDHOC_METHOD_3:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_ERROR_GENERIC_ERROR;
}

static size_t calc_mac_2_input_len(const struct edhoc_context *ctx,
				   const struct edhoc_auth_creds *auth_cred,
				   enum edhoc_role role)
{
	if (NULL == ctx || NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	const size_t nr_of_items = 1;
	size_t len = 0;

	/* C_R. */
	const struct edhoc_connection_id *cid = NULL;

	switch (role) {
	case initiator:
		cid = &ctx->peer_cid;
		break;
	case responder:
		cid = &ctx->cid;
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	switch (cid->encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		len = sizeof(cid->int_value);
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		len += cid->bstr_length;
		len += cbor_bstr_overhead(cid->bstr_length);
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* ID_CRED_R. */
	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		len += cbor_map_overhead(nr_of_items);

		switch (auth_cred->key_id.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			len += cbor_int_mem_req(auth_cred->key_id.key_id_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			len += auth_cred->key_id.key_id_bstr_length;
			len += cbor_bstr_overhead(
				auth_cred->key_id.key_id_bstr_length);
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
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

		switch (auth_cred->x509_hash.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			len += cbor_int_mem_req(auth_cred->x509_hash.alg_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			len += auth_cred->x509_hash.alg_bstr_length;
			len += cbor_bstr_overhead(
				auth_cred->x509_hash.alg_bstr_length);
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		len += auth_cred->x509_hash.cert_fp_len;
		len += cbor_bstr_overhead(auth_cred->x509_hash.cert_fp_len);
		break;

	default:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	/* TH_2. */
	len += ctx->th_len;
	len += cbor_bstr_overhead(ctx->th_len);

	/* CRED_R. */
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

	/* EAD_2. */
	for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
		len += cbor_int_mem_req(ctx->ead_token[i].label);
		len += ctx->ead_token[i].value_len;
		len += cbor_bstr_overhead(ctx->ead_token[i].value_len);
	}

	return len;
}

static int calc_mac_2_context(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_cred,
			      enum edhoc_role role,
			      struct cbor_items *cbor_items)
{
	if (NULL == ctx || NULL == auth_cred || NULL == cbor_items)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	const size_t nr_of_items = 1;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	cbor_items->conn_id = &cbor_items->buf[0];

	/* C_R length. */
	const struct edhoc_connection_id *cid = NULL;

	switch (role) {
	case initiator:
		cid = &ctx->peer_cid;
		break;
	case responder:
		cid = &ctx->cid;
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	switch (cid->encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		len = sizeof(cid->int_value);
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		len += cid->bstr_length + 1;
		len += cbor_bstr_overhead(cid->bstr_length);
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	cbor_items->conn_id_len = len;

	/* Cborise C_R. */
	switch (cid->encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
		const int32_t value = cid->int_value;
		len = 0;
		ret = cbor_encode_integer_type_int_type(cbor_items->conn_id,
							cbor_items->conn_id_len,
							&value, &len);
		break;
	}
	case EDHOC_CID_TYPE_BYTE_STRING: {
		const struct zcbor_string cbor_bstr = {
			.value = cid->bstr_value,
			.len = cid->bstr_length,
		};
		len = 0;
		ret = cbor_encode_byte_string_type_bstr_type(
			cbor_items->conn_id, cbor_items->conn_id_len,
			&cbor_bstr, &len);
		break;
	}
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	cbor_items->conn_id_len = len;

	/* ID_CRED_R length. */
	len = cbor_items->conn_id_len;
	cbor_items->id_cred_r = &cbor_items->buf[cbor_items->conn_id_len];

	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		len += cbor_map_overhead(nr_of_items);

		switch (auth_cred->key_id.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			if (true ==
			    is_cbor_one_byte_int(auth_cred->key_id.key_id_int))
				cbor_items->id_cred_r_is_cob = true;

			len += cbor_int_mem_req(auth_cred->key_id.key_id_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			len += auth_cred->key_id.key_id_bstr_length;
			len += cbor_bstr_overhead(
				auth_cred->key_id.key_id_bstr_length);
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
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

		switch (auth_cred->x509_hash.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			len += cbor_int_mem_req(auth_cred->x509_hash.alg_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			len += auth_cred->x509_hash.alg_bstr_length;
			len += cbor_bstr_overhead(
				auth_cred->x509_hash.alg_bstr_length);
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		len += auth_cred->x509_hash.cert_fp_len;
		len += cbor_bstr_overhead(auth_cred->x509_hash.cert_fp_len);
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	cbor_items->id_cred_r_len = len;

	/* Cborise ID_CRED_R. */
	struct id_cred_x cbor_id_cred_r = { 0 };

	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		cbor_id_cred_r._id_cred_x_kid_present = true;

		switch (auth_cred->key_id.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			cbor_id_cred_r._id_cred_x_kid._id_cred_x_kid_choice =
				_id_cred_x_kid_int;
			cbor_id_cred_r._id_cred_x_kid._id_cred_x_kid_int =
				auth_cred->key_id.key_id_int;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			cbor_id_cred_r._id_cred_x_kid._id_cred_x_kid_choice =
				_id_cred_x_kid_bstr;
			cbor_id_cred_r._id_cred_x_kid._id_cred_x_kid_bstr.value =
				auth_cred->key_id.key_id_bstr;
			cbor_id_cred_r._id_cred_x_kid._id_cred_x_kid_bstr.len =
				auth_cred->key_id.key_id_bstr_length;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		if (cbor_items->id_cred_r_is_cob) {
			len = 0;
			ret = cbor_encode_integer_type_int_type(
				(uint8_t *)&cbor_items->id_cred_r_cob_val,
				sizeof(cbor_items->id_cred_r_cob_val),
				&auth_cred->key_id.key_id_int, &len);

			if (ZCBOR_SUCCESS != ret)
				return EDHOC_ERROR_CBOR_FAILURE;
		}

		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		cbor_id_cred_r._id_cred_x_x5chain_present = true;
		cbor_id_cred_r._id_cred_x_x5chain._id_cred_x_x5chain.value =
			auth_cred->x509_chain.cert;
		cbor_id_cred_r._id_cred_x_x5chain._id_cred_x_x5chain.len =
			auth_cred->x509_chain.cert_len;
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		cbor_id_cred_r._id_cred_x_x5t_present = true;
		cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t_hash.value =
			auth_cred->x509_hash.cert_fp;
		cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t_hash.len =
			auth_cred->x509_hash.cert_fp_len;

		switch (auth_cred->x509_hash.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t_alg_choice =
				_id_cred_x_x5t_alg_int;
			cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t_alg_int =
				auth_cred->x509_hash.alg_int;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t_alg_choice =
				_id_cred_x_x5t_alg_bstr;
			cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t_alg_bstr
				.value = auth_cred->x509_hash.alg_bstr;
			cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t_alg_bstr
				.len = auth_cred->x509_hash.alg_bstr_length;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;
	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	len = 0;
	ret = cbor_encode_id_cred_x(cbor_items->id_cred_r,
				    cbor_items->id_cred_r_len, &cbor_id_cred_r,
				    &len);
	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	cbor_items->id_cred_r_len = len;

	/* TH_2 length. */
	len = ctx->th_len;
	cbor_items->th_2 = &cbor_items->id_cred_r[cbor_items->id_cred_r_len];
	cbor_items->th_2_len = cbor_bstr_overhead(len) + len;

	/* Cborise TH_2. */
	const struct zcbor_string cbor_th_2 = {
		.value = ctx->th,
		.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		cbor_items->th_2, cbor_items->th_2_len, &cbor_th_2, &len);

	if (ZCBOR_SUCCESS != ret || cbor_items->th_2_len != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* CRED_R length. */
	cbor_items->cred_r = &cbor_items->th_2[cbor_items->th_2_len];
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

	cbor_items->cred_r_len = len;

	/* Cborise CRED_R. */
	struct zcbor_string cbor_cred_r = { 0 };

	switch (auth_cred->label) {
	case EDHOC_COSE_HEADER_KID:
		cbor_cred_r.value = auth_cred->key_id.cred;
		cbor_cred_r.len = auth_cred->key_id.cred_len;
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		cbor_cred_r.value = auth_cred->x509_chain.cert;
		cbor_cred_r.len = auth_cred->x509_chain.cert_len;
		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		cbor_cred_r.value = auth_cred->x509_hash.cert;
		cbor_cred_r.len = auth_cred->x509_hash.cert_len;
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		cbor_items->cred_r, cbor_items->cred_r_len, &cbor_cred_r, &len);

	if (ZCBOR_SUCCESS != ret || cbor_items->cred_r_len != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* EAD_2 length. */
	if (0 != ctx->nr_of_ead_tokens) {
		len = 0;
		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			len += cbor_int_mem_req(ctx->ead_token[i].label);
			len += 1; // cbor boolean
			len += ctx->ead_token[i].value_len;
			len += cbor_bstr_overhead(ctx->ead_token[i].value_len);
		}

		cbor_items->is_ead_2 = true;
		cbor_items->ead_2 = &cbor_items->cred_r[cbor_items->cred_r_len];
		cbor_items->ead_2_len = len;
	} else {
		cbor_items->is_ead_2 = false;
		cbor_items->ead_2 = NULL;
		cbor_items->ead_2_len = 0;
	}

	/* Cborise EAD_2 if present. */
	if (cbor_items->is_ead_2) {
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
		ret = cbor_encode_ead(cbor_items->ead_2, cbor_items->ead_2_len,
				      &ead_tokens, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		cbor_items->ead_2_len = len;
	}

	const size_t encoded_bytes =
		cbor_items->conn_id_len + cbor_items->id_cred_r_len +
		cbor_items->th_2_len + cbor_items->cred_r_len +
		cbor_items->ead_2_len;

	if (encoded_bytes > cbor_items->buf_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	cbor_items->buf_len = encoded_bytes;
	return EDHOC_SUCCESS;
}

static int calc_mac_2(const struct edhoc_context *ctx,
		      const struct cbor_items *cbor_items, uint8_t *mac_2,
		      size_t mac_2_len)
{
	if (NULL == ctx || NULL == cbor_items || NULL == mac_2 ||
	    0 == mac_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_2,
		._info_context.value = cbor_items->buf,
		._info_context.len = cbor_items->buf_len,
		._info_length = mac_2_len,
	};

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_2);
	len += cbor_items->buf_len + cbor_bstr_overhead(cbor_items->buf_len);
	len += cbor_int_mem_req(mac_2_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "MAC_2 info", info, len);

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
				     key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(key_id, info, len, mac_2, mac_2_len);
	ctx->keys.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int calc_sign_or_mac_2(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_cred,
			      const struct cbor_items *cbor_items,
			      const uint8_t *mac_2, size_t mac_2_len,
			      uint8_t *sign, size_t sign_len)
{
	if (NULL == ctx || NULL == auth_cred || NULL == cbor_items ||
	    NULL == mac_2 || 0 == mac_2_len || NULL == sign || 0 == sign_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct sig_structure cose_sign_1 = {
		._sig_structure_protected.value = cbor_items->id_cred_r,
		._sig_structure_protected.len = cbor_items->id_cred_r_len,
		._sig_structure_external_aad.value = cbor_items->th_2,
		._sig_structure_external_aad.len = cbor_items->th_2_len +
						   cbor_items->cred_r_len +
						   cbor_items->ead_2_len,
		._sig_structure_payload.value = mac_2,
		._sig_structure_payload.len = mac_2_len,
	};

	size_t len = 0;
	len += sizeof("Signature1") + cbor_tstr_overhead(sizeof("Signature1"));
	len += cbor_items->id_cred_r_len +
	       cbor_bstr_overhead(cbor_items->id_cred_r_len);
	len += cbor_items->th_2_len + cbor_items->cred_r_len +
	       cbor_items->ead_2_len +
	       cbor_bstr_overhead(cbor_items->th_2_len +
				  cbor_items->cred_r_len +
				  cbor_items->ead_2_len);
	len += mac_2_len + cbor_int_mem_req(mac_2_len);

	uint8_t cose_sign_1_buf[len];
	memset(cose_sign_1_buf, 0, sizeof(cose_sign_1_buf));

	len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					ARRAY_SIZE(cose_sign_1_buf),
					&cose_sign_1, &len);
	const size_t cose_sign_1_buf_len = len;

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	len = 0;
	ret = ctx->crypto.signature(auth_cred->priv_key_id, cose_sign_1_buf,
				    cose_sign_1_buf_len, sign, sign_len, &len);

	if (EDHOC_SUCCESS != ret || sign_len != len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct cbor_items *cbor_items,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t offset = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
		size_t len = 0;
		const int32_t value = ctx->cid.int_value;
		ret = cbor_encode_integer_type_int_type(ptxt, ptxt_len - offset,
							&value, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		offset += len;
		break;
	}
	case EDHOC_CID_TYPE_BYTE_STRING: {
		size_t len = 0;
		const struct zcbor_string input = {
			.value = ctx->cid.bstr_value,
			.len = ctx->cid.bstr_length,
		};
		ret = cbor_encode_byte_string_type_bstr_type(
			ptxt, ptxt_len - offset, &input, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		offset += len;
		break;
	}
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (cbor_items->id_cred_r_is_cob) {
		memcpy(&ptxt[offset], &cbor_items->id_cred_r_cob_val,
		       (size_t)cbor_items->id_cred_r_is_cob);
		offset += cbor_items->id_cred_r_is_cob;
	} else {
		memcpy(&ptxt[offset], cbor_items->id_cred_r,
		       cbor_items->id_cred_r_len);
		offset += cbor_items->id_cred_r_len;
	}

	const struct zcbor_string cbor_sign_or_mac_2 = {
		.value = sign,
		.len = sign_len,
	};

	size_t len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&ptxt[offset], sign_len + cbor_bstr_overhead(sign_len),
		&cbor_sign_or_mac_2, &len);

	if (ZCBOR_SUCCESS != ret ||
	    (sign_len + cbor_bstr_overhead(sign_len)) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len;

	if (cbor_items->is_ead_2) {
		memcpy(&ptxt[offset], cbor_items->ead_2, cbor_items->ead_2_len);
		offset += cbor_items->ead_2_len;
	}

	if (offset > ptxt_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	return EDHOC_SUCCESS;
}

static int compute_keystream(const struct edhoc_context *ctx,
			     const uint8_t *prk_2e, size_t prk_2e_len,
			     uint8_t *keystream, size_t keystream_len)
{
	if (NULL == ctx || NULL == prk_2e || 0 == prk_2e_len ||
	    NULL == keystream || 0 == keystream_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2,
		._info_context.value = ctx->th,
		._info_context.len = ctx->th_len,
		._info_length = keystream_len,
	};

	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2);
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += cbor_int_mem_req(keystream_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret || ARRAY_SIZE(info) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_EXPAND, prk_2e, prk_2e_len,
				     key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(key_id, info, ARRAY_SIZE(info), keystream,
				 keystream_len);
	ctx->keys.destroy_key(key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static void xor_arrays(uint8_t *dst, const uint8_t *src, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		dst[i] ^= src[i];
}

static int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ctxt, size_t ctxt_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len)
{
	if (NULL == ctx || NULL == ctxt || 0 == ctxt_len || NULL == msg_2 ||
	    0 == msg_2_size || NULL == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t offset = 0;

	size_t len = 0;
	len += ctx->dh_pub_key_len;
	len += ctxt_len;

	uint8_t buffer[len];
	memset(buffer, 0, sizeof(buffer));

	memcpy(&buffer[offset], ctx->dh_pub_key, ctx->dh_pub_key_len);
	offset += ctx->dh_pub_key_len;

	memcpy(&buffer[offset], ctxt, ctxt_len);
	offset += ctxt_len;

	if (ARRAY_SIZE(buffer) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	const struct zcbor_string cbor_msg_2 = {
		.value = buffer,
		.len = ARRAY_SIZE(buffer),
	};

	ret = cbor_encode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_size,
						     &cbor_msg_2, msg_2_len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_ciphertext_2_len(const struct edhoc_context *ctx,
				    const uint8_t *msg_2, size_t msg_2_len,
				    size_t *ctxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (len > msg_2_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	len = dec_msg_2.len;
	len -= ctx->csuite[ctx->chosen_csuite_idx].ecc_key_length;

	*ctxt_len = len;
	return EDHOC_SUCCESS;
}

static int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (len > msg_2_len)
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;

	/* Get Diffie-Hellmann peer public key (G_Y). */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];
	ctx->dh_peer_pub_key_len = csuite.ecc_key_length;
	memcpy(ctx->dh_peer_pub_key, dec_msg_2.value, ctx->dh_peer_pub_key_len);

	/* Get CIPHERTEXT_2. */
	const size_t offset = ctx->dh_peer_pub_key_len;
	memcpy(ctxt_2, &dec_msg_2.value[offset], ctxt_2_len);

	return EDHOC_SUCCESS;
}

static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt)
{
	if (NULL == ctx || NULL == ptxt || 0 == ptxt_len || NULL == parsed_ptxt)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_2 cbor_ptxt_2 = { 0 };
	ret = cbor_decode_plaintext_2(ptxt, ptxt_len, &cbor_ptxt_2, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* C_R */
	switch (cbor_ptxt_2._plaintext_2_C_R_choice) {
	case _plaintext_2_C_R_int:
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    (int8_t)cbor_ptxt_2._plaintext_2_C_R_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    (int8_t)cbor_ptxt_2._plaintext_2_C_R_int)
			return EDHOC_ERROR_NOT_PERMITTED;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx->peer_cid.int_value =
			(int8_t)cbor_ptxt_2._plaintext_2_C_R_int;
		break;

	case _plaintext_2_C_R_bstr:
		if (ARRAY_SIZE(ctx->peer_cid.bstr_value) <
		    cbor_ptxt_2._plaintext_2_C_R_bstr.len)
			return EDHOC_ERROR_BUFFER_TOO_SMALL;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
		ctx->peer_cid.bstr_length =
			cbor_ptxt_2._plaintext_2_C_R_bstr.len;
		memcpy(ctx->peer_cid.bstr_value,
		       cbor_ptxt_2._plaintext_2_C_R_bstr.value,
		       cbor_ptxt_2._plaintext_2_C_R_bstr.len);
		break;

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* ID_CRED_R */
	switch (cbor_ptxt_2._plaintext_2_ID_CRED_R_choice) {
	case _plaintext_2_ID_CRED_R_int:
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_INTEGER;
		parsed_ptxt->auth_cred.key_id.key_id_int =
			cbor_ptxt_2._plaintext_2_ID_CRED_R_int;
		break;

	case _plaintext_2_ID_CRED_R_bstr:
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_BYTE_STRING;
		parsed_ptxt->auth_cred.key_id.key_id_bstr_length =
			cbor_ptxt_2._plaintext_2_ID_CRED_R_bstr.len;
		memcpy(parsed_ptxt->auth_cred.key_id.key_id_bstr,
		       cbor_ptxt_2._plaintext_2_ID_CRED_R_bstr.value,
		       cbor_ptxt_2._plaintext_2_ID_CRED_R_bstr.len);
		break;

	case _plaintext_2_ID_CRED_R__map: {
		const struct map *cbor_map =
			&cbor_ptxt_2._plaintext_2_ID_CRED_R__map;

		if (cbor_map->_map_x5chain_present) {
			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_CHAIN;
			parsed_ptxt->auth_cred.x509_chain.cert =
				cbor_map->_map_x5chain._map_x5chain.value;
			parsed_ptxt->auth_cred.x509_chain.cert_len =
				cbor_map->_map_x5chain._map_x5chain.len;
			break;
		}

		if (cbor_map->_map_x5t_present) {
			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_HASH;
			parsed_ptxt->auth_cred.x509_hash.cert_fp =
				cbor_map->_map_x5t._map_x5t_hash.value;
			parsed_ptxt->auth_cred.x509_hash.cert_fp_len =
				cbor_map->_map_x5t._map_x5t_hash.len;

			switch (cbor_map->_map_x5t._map_x5t_alg_choice) {
			case _map_x5t_alg_int:
				parsed_ptxt->auth_cred.x509_hash.alg_int =
					cbor_map->_map_x5t._map_x5t_alg_int;
				break;
			case _map_x5t_alg_bstr:
				parsed_ptxt->auth_cred.x509_hash
					.alg_bstr_length =
					cbor_map->_map_x5t._map_x5t_alg_bstr.len;
				memcpy(parsed_ptxt->auth_cred.x509_hash.alg_bstr,
				       cbor_map->_map_x5t._map_x5t_alg_bstr
					       .value,
				       cbor_map->_map_x5t._map_x5t_alg_bstr.len);
				break;
			default:
				return EDHOC_ERROR_NOT_PERMITTED;
			}

			break;
		}
	}
	}

	/* Sign_or_MAC_2 */
	parsed_ptxt->sign_or_mac =
		cbor_ptxt_2._plaintext_2_Signature_or_MAC_2.value;
	parsed_ptxt->sign_or_mac_len =
		cbor_ptxt_2._plaintext_2_Signature_or_MAC_2.len;

	/* EAD_2 if present */
	if (cbor_ptxt_2._plaintext_2_EAD_2_present) {
		ctx->nr_of_ead_tokens =
			cbor_ptxt_2._plaintext_2_EAD_2._ead_x_count;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				cbor_ptxt_2._plaintext_2_EAD_2._ead_x[i]
					._ead_x_ead_label;
			ctx->ead_token[i].value =
				cbor_ptxt_2._plaintext_2_EAD_2._ead_x[i]
					._ead_x_ead_value.value;
			ctx->ead_token[i].value_len =
				cbor_ptxt_2._plaintext_2_EAD_2._ead_x[i]
					._ead_x_ead_value.len;
		}
	}

	return EDHOC_SUCCESS;
}

static int verify_sign_or_mac_2(const struct edhoc_context *ctx,
				const struct cbor_items *cbor_items,
				const struct plaintext *parsed_ptxt,
				const uint8_t *pub_key, size_t pub_key_len,
				const uint8_t *mac_2, size_t mac_2_len)
{
	if (NULL == ctx || NULL == cbor_items || NULL == parsed_ptxt ||
	    NULL == pub_key || 0 == pub_key_len || NULL == mac_2 ||
	    0 == mac_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	const struct sig_structure cose_sign_1 = {
		._sig_structure_protected.value = cbor_items->id_cred_r,
		._sig_structure_protected.len = cbor_items->id_cred_r_len,
		._sig_structure_external_aad.value = cbor_items->th_2,
		._sig_structure_external_aad.len = cbor_items->th_2_len +
						   cbor_items->cred_r_len +
						   cbor_items->ead_2_len,
		._sig_structure_payload.value = mac_2,
		._sig_structure_payload.len = mac_2_len,
	};

	len = 0;
	len += sizeof("Signature1") + cbor_tstr_overhead(sizeof("Signature1"));
	len += cbor_items->id_cred_r_len +
	       cbor_bstr_overhead(cbor_items->id_cred_r_len);
	len += cbor_items->th_2_len + cbor_items->cred_r_len +
	       cbor_items->ead_2_len +
	       cbor_bstr_overhead(cbor_items->th_2_len +
				  cbor_items->cred_r_len +
				  cbor_items->ead_2_len);
	len += mac_2_len + cbor_bstr_overhead(mac_2_len);

	uint8_t cose_sign_1_buf[len];
	memset(cose_sign_1_buf, 0, sizeof(cose_sign_1_buf));

	len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					ARRAY_SIZE(cose_sign_1_buf),
					&cose_sign_1, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_VERIFY, pub_key, pub_key_len,
				     key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.verify(key_id, cose_sign_1_buf, len,
				 parsed_ptxt->sign_or_mac,
				 parsed_ptxt->sign_or_mac_len);
	ctx->keys.destroy_key(key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int calc_th_3(struct edhoc_context *ctx,
		     const struct cbor_items *cbor_items, const uint8_t *ptxt,
		     size_t ptxt_len)
{
	if (NULL == ctx || NULL == cbor_items || NULL == ptxt || 0 == ptxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += ptxt_len;
	len += cbor_items->cred_r_len;

	uint8_t th_3[len];
	memset(th_3, 0, sizeof(th_3));

	size_t offset = 0;
	struct zcbor_string bstr = (struct zcbor_string){
		.value = ctx->th,
		.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&th_3[offset], ARRAY_SIZE(th_3), &bstr, &len);
	offset += len;

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	memcpy(&th_3[offset], ptxt, ptxt_len);
	offset += ptxt_len;

	memcpy(&th_3[offset], cbor_items->cred_r, cbor_items->cred_r_len);
	offset += cbor_items->cred_r_len;

	if (ARRAY_SIZE(th_3) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	/* Calculate TH_3. */
	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	size_t hash_len = 0;
	ret = ctx->crypto.hash(th_3, ARRAY_SIZE(th_3), ctx->th, ctx->th_len,
			       &hash_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_3;
	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 2:
 * 	1.  Choose most preferred cipher suite.
 *	2.  Generate ephemeral Diffie-Hellmann key pair.
 *	3.  Compute Diffie-Hellmann shared secret.
 *	4.  Compute Transcript Hash 2 (TH_2).
 *	5a. Compute Pseudo Random Key 2 (PRK_2e).
 *      5b. Copy of Pseudo Random Key 2 for keystream (step 12).
 *	6.  Fetch authentication credentials.
 *      7.  Compose EAD_2 if present.
 *      8.  Compute psuedo random key (PRK_3e2m).
 *	9a. Compute required buffer length for context_2.
 *	9b. Cborise items required by context_2.
 *	9c. Compute Message Authentication Code (MAC_2).
 *	10. Compute signature if needed (Signature_or_MAC_2).
 *	11. Prepare plaintext (PLAINTEXT_2).
 *	12. Compute key stream (KEYSTREAM_2).
 *      13. Compute Transcript Hash 3 (TH_3).
 *	14. Compute ciphertext (CIPHERTEXT_2).
 *	15. Cborise items for message 2.
 *      16. Clean-up EAD tokens.
 */
int edhoc_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
			    size_t msg_2_size, size_t *msg_2_len)
{
	if (NULL == ctx || msg_2 == NULL || 0 == msg_2_size ||
	    NULL == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_RECEIVED_M1 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;

	ctx->status = EDHOC_SM_ABORTED;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Generate ephemeral Diffie-Hellmann key pair. */
	switch (ctx->method) {
	case EDHOC_METHOD_0:
		ret = gen_dh_keys(ctx);
		break;

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_2:
	case EDHOC_METHOD_3:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "G_Y", ctx->dh_pub_key,
			    ctx->dh_pub_key_len);
		ctx->logger(ctx->user_ctx, "Y", ctx->dh_priv_key,
			    ctx->dh_priv_key_len);
	}

	/* 3. Compute Diffie-Hellmann shared secret. */
	ret = calc_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = calc_th_2(ctx, responder);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 5a. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = compute_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 5b. Copy of Pseudo Random Key 2 for keystream (step 12). */
	uint8_t prk_2e[ctx->prk_len];
	memcpy(prk_2e, ctx->prk, sizeof(prk_2e));

	/* 6. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_cred = { 0 };
	ret = ctx->cred.fetch(ctx->user_ctx, &auth_cred);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/* 7. Compose EAD_2 if present. */
	if (NULL != ctx->ead.compose && 0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->ead.compose(ctx->user_ctx, EDHOC_MSG_2,
				       ctx->ead_token,
				       ARRAY_SIZE(ctx->ead_token) - 1,
				       &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens)
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	/* 8. Compute psuedo random key (PRK_3e2m). */
	ret = compute_prk_3e2m(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_3e2m", ctx->prk, ctx->prk_len);

	/* 9a. Compute required buffer length for context_2. */
	const size_t context_2_len =
		calc_mac_2_input_len(ctx, &auth_cred, responder);

	if (0 == context_2_len)
		return EDHOC_ERROR_INVALID_MAC_2;

	uint8_t mac_2_content[sizeof(struct cbor_items) + context_2_len];
	memset(mac_2_content, 0, sizeof(mac_2_content));

	struct cbor_items *cbor_items = (struct cbor_items *)mac_2_content;
	cbor_items->buf_len = context_2_len;

	/* 9b. Cborise items required by context_2. */
	ret = calc_mac_2_context(ctx, &auth_cred, responder, cbor_items);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "C_R", cbor_items->conn_id,
			    cbor_items->conn_id_len);
		ctx->logger(ctx->user_ctx, "ID_CRED_R", cbor_items->id_cred_r,
			    cbor_items->id_cred_r_len);
		ctx->logger(ctx->user_ctx, "TH_2", cbor_items->th_2,
			    cbor_items->th_2_len);
		ctx->logger(ctx->user_ctx, "CRED_R", cbor_items->cred_r,
			    cbor_items->cred_r_len);
	}

	/* 9c. Compute Message Authentication Code (MAC_2). */
	uint8_t mac_2[csuite.hash_length];
	memset(mac_2, 0, sizeof(mac_2));

	ret = calc_mac_2(ctx, cbor_items, mac_2, ARRAY_SIZE(mac_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "MAC_2", mac_2, ARRAY_SIZE(mac_2));

	/* 10. Compute signature if needed (Signature_or_MAC_2). */
	uint8_t sign[csuite.ecc_sign_length];
	memset(sign, 0, sizeof(sign));

	switch (ctx->method) {
	case EDHOC_METHOD_0:
		ret = calc_sign_or_mac_2(ctx, &auth_cred, cbor_items, mac_2,
					 ARRAY_SIZE(mac_2), sign,
					 ARRAY_SIZE(sign));
		break;

	case EDHOC_METHOD_2:
	case EDHOC_METHOD_1:
	case EDHOC_METHOD_3:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "Signature_or_MAC_2", sign,
			    ARRAY_SIZE(sign));

	/* 11. Prepare plaintext (PLAINTEXT_2). */
	size_t plaintext_len = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		plaintext_len += sizeof(ctx->cid.int_value);
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		plaintext_len += ctx->cid.bstr_length;
		plaintext_len += cbor_bstr_overhead(ctx->cid.bstr_length);
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}
	plaintext_len +=
		(cbor_items->id_cred_r_is_cob) ? 1 : cbor_items->id_cred_r_len;
	plaintext_len += ARRAY_SIZE(sign);
	plaintext_len += cbor_bstr_overhead(ARRAY_SIZE(sign));
	plaintext_len += cbor_items->ead_2_len;

	uint8_t plaintext[plaintext_len];
	memset(plaintext, 0, sizeof(plaintext));

	ret = prepare_plaintext_2(ctx, cbor_items, sign, ARRAY_SIZE(sign),
				  plaintext, ARRAY_SIZE(plaintext));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_2", plaintext,
			    ARRAY_SIZE(plaintext));

	/* 12. Compute key stream (KEYSTREAM_2). */
	uint8_t keystream[ARRAY_SIZE(plaintext)];
	memset(keystream, 0, sizeof(keystream));

	ret = compute_keystream(ctx, prk_2e, ARRAY_SIZE(prk_2e), keystream,
				ARRAY_SIZE(keystream));
	memset(prk_2e, 0, sizeof(prk_2e));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "KEYSTREAM_2", keystream,
			    ARRAY_SIZE(keystream));

	/* 13. Compute Transcript Hash 3 (TH_3). */
	ret = calc_th_3(ctx, cbor_items, plaintext, ARRAY_SIZE(plaintext));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 14. Compute ciphertext (CIPHERTEXT_2). */
	xor_arrays(plaintext, keystream, ARRAY_SIZE(plaintext));
	const uint8_t *ciphertext = plaintext;
	const size_t ciphertext_len = ARRAY_SIZE(plaintext);

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_2", ciphertext,
			    ciphertext_len);

	/* 15. Cborise items for message 2. */
	ret = prepare_message_2(ctx, ciphertext, ciphertext_len, msg_2,
				msg_2_size, msg_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "message_2", msg_2, *msg_2_len);

	/* 16. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_WAIT_M3;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 2:
 * 	1.  Compute required length for ciphertext.
 *      2.  Decode cborised message 2.
 *      3.  Compute Diffie-Hellmann shared secret (G_XY).
 *      4.  Compute Transcript Hash 2 (TH_2).
 *      5.  Compute Pseudo Random Key 2 (PRK_2e).
 *      6.  Compute key stream (KEYSTREAM_2).
 *      7.  Compute plaintext (PLAINTEXT_2).
 *      8.  Parse plaintext (PLAINTEXT_2).
 *      9.  Process EAD if present.
 *      10. Verify if credentials from peer are trusted.
 *      11. Compute psuedo random key (PRK_3e2m).
 *      12. Compute required buffer length for context_2.
 *      13. Cborise items required by context_2.
 *      14. Compute Message Authentication Code (MAC_2).
 *      15. Verify Signature_or_MAC_2.
 *      16. Compute Transcript Hash 3 (TH_3).
 *      17. Clean-up EAD tokens.
 */
int edhoc_message_2_process(struct edhoc_context *ctx, const uint8_t *msg_2,
			    size_t msg_2_len)
{
	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_WAIT_M2 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;

	ctx->status = EDHOC_SM_ABORTED;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* 1. Compute required length for ciphertext. */
	ret = compute_ciphertext_2_len(ctx, msg_2, msg_2_len, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	uint8_t ciphertext_2[len];
	memset(ciphertext_2, 0, sizeof(ciphertext_2));

	/* 2. Decode cborised message 2. */
	ret = parse_msg_2(ctx, msg_2, msg_2_len, ciphertext_2,
			  ARRAY_SIZE(ciphertext_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_2", ciphertext_2,
			    ARRAY_SIZE(ciphertext_2));

	/* 3. Compute Diffie-Hellmann shared secret (G_XY). */
	ret = calc_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = calc_th_2(ctx, initiator);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = compute_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 6. Compute key stream (KEYSTREAM_2). */
	uint8_t keystream[ARRAY_SIZE(ciphertext_2)];
	memset(keystream, 0, sizeof(keystream));

	ret = compute_keystream(ctx, ctx->prk, ctx->prk_len, keystream,
				ARRAY_SIZE(keystream));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "KEYSTREAM", keystream,
			    ARRAY_SIZE(keystream));

	/* 7. Compute plaintext (PLAINTEXT_2). */
	xor_arrays(ciphertext_2, keystream, ARRAY_SIZE(ciphertext_2));
	const uint8_t *plaintext = ciphertext_2;
	const size_t plaintext_len = ARRAY_SIZE(ciphertext_2);

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_2", plaintext,
			    plaintext_len);

	/* 8. Parse plaintext (PLAINTEXT_2). */
	struct plaintext parsed_ptxt = { 0 };
	ret = parse_plaintext(ctx, plaintext, plaintext_len, &parsed_ptxt);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger) {
		switch (ctx->peer_cid.encode_type) {
		case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
			ctx->logger(ctx->user_ctx, "C_R",
				    (const uint8_t *)&ctx->peer_cid.int_value,
				    sizeof(ctx->peer_cid.int_value));
			break;
		case EDHOC_CID_TYPE_BYTE_STRING:
			ctx->logger(ctx->user_ctx, "C_R",
				    ctx->peer_cid.bstr_value,
				    ctx->peer_cid.bstr_length);
			break;

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	/* 9. Process EAD if present. */
	if (NULL != ctx->ead.process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead.process(ctx->user_ctx, EDHOC_MSG_2,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	/* 10. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;

	ret = ctx->cred.verify(ctx->user_ctx, &parsed_ptxt.auth_cred, &pub_key,
			       &pub_key_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/* 11. Compute psuedo random key (PRK_3e2m). */
	ret = compute_prk_3e2m(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	/* 12. Compute required buffer length for context_2. */
	const size_t context_2_len =
		calc_mac_2_input_len(ctx, &parsed_ptxt.auth_cred, initiator);

	if (0 == context_2_len)
		return EDHOC_ERROR_INVALID_MAC_2;

	uint8_t mac_2_content[sizeof(struct cbor_items) + context_2_len];
	memset(mac_2_content, 0, sizeof(mac_2_content));

	struct cbor_items *cbor_items = (struct cbor_items *)mac_2_content;
	cbor_items->buf_len = context_2_len;

	/* 13. Cborise items required by context_2. */
	ret = calc_mac_2_context(ctx, &parsed_ptxt.auth_cred, initiator,
				 cbor_items);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "context_2", cbor_items->buf,
			    cbor_items->buf_len);

	/* 14. Compute Message Authentication Code (MAC_2). */
	uint8_t mac_2[ctx->csuite[ctx->chosen_csuite_idx].hash_length];
	memset(mac_2, 0, sizeof(mac_2));

	ret = calc_mac_2(ctx, cbor_items, mac_2, ARRAY_SIZE(mac_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "MAC_2", mac_2, ARRAY_SIZE(mac_2));

	/* 15. Verify Signature_or_MAC_2. */
	ret = verify_sign_or_mac_2(ctx, cbor_items, &parsed_ptxt, pub_key,
				   pub_key_len, mac_2, ARRAY_SIZE(mac_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

	/* 16. Compute Transcript Hash 3 (TH_3). */
	ret = calc_th_3(ctx, cbor_items, plaintext, plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 17. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_VERIFIED_M2;
	return EDHOC_SUCCESS;
}
