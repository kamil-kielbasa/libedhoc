/**
 * \file    edhoc_message_2.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 2.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wreserved-identifier"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

/* CBOR headers: */
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

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/**
 * \brief Helper structure for CBOR encoding. 
 */
struct cbor_items {
	uint8_t *conn_id;
	size_t conn_id_len;

	uint8_t *id_cred_r;
	size_t id_cred_r_len;

	bool id_cred_r_is_comp_enc; // cob = cbor one byte
	enum edhoc_encode_type id_cred_r_enc_type;
	int32_t id_cred_r_int;
	uint8_t id_cred_r_bstr[EDHOC_CRED_KEY_ID_LEN + 1];
	size_t id_cred_r_bstr_len;

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
 * \brief Compute ECDH shared secret (G_XY).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int comp_dh_secret(struct edhoc_context *ctx);

/** 
 * \brief Compute transcript hash 2 (TH_2).
 *
 * \param[in,out] ctx		EDHOC context.
 * \param role                  EDHOC role.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int comp_th_2(struct edhoc_context *ctx, enum edhoc_role role);

/** 
 * \brief Compute psuedo random key (PRK_2e).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int comp_prk_2e(struct edhoc_context *ctx);

/** 
 * \brief Compute psuedo random key (PRK_3e2m).
 *
 * \param[in] role              EDHOC role.
 * \param[in,out] ctx		EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public static DH key. 
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_prk_3e2m(enum edhoc_role role, struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len);

/** 
 * \brief Compute memory required for input (context_2) for for MAC_2.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param role                  EDHOC role.
 * \param[out] context_2_len    On success, length of context_2 for MAC_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_mac_2_input_len(const struct edhoc_context *ctx,
				const struct edhoc_auth_creds *auth_cred,
				enum edhoc_role role, size_t *context_2_len);

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
static int gen_mac_2_context(const struct edhoc_context *ctx,
			     const struct edhoc_auth_creds *auth_cred,
			     enum edhoc_role role,
			     struct cbor_items *cbor_items);

/**
 * \brief Get required MAC_2 length.
 * 
 * \param role                  EDHOC role.
 * \param[in] ctx               EDHOC context.
 * \param[out] mac_2_len        On success, length of MAC_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int get_mac_2_len(enum edhoc_role role, const struct edhoc_context *ctx,
			 size_t *mac_2_len);

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
static int comp_mac_2(const struct edhoc_context *ctx,
		      const struct cbor_items *cbor_items, uint8_t *mac_2,
		      size_t mac_2_len);

/**
 * \brief Compute required length for Signature_or_MAC_2.
 * 
 * \param role                          EDHOC role.
 * \param[in] ctx                       EDHOC context.
 * \param[out] sign_or_mac_2_len        On success, length of Signature_or_MAC_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_sign_or_mac_2_len(enum edhoc_role role,
				  const struct edhoc_context *ctx,
				  size_t *sign_or_mac_2_len);

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
static int comp_sign_or_mac_2(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_cred,
			      const struct cbor_items *cbor_items,
			      const uint8_t *mac_2, size_t mac_2_len,
			      uint8_t *sign, size_t sign_len);

/** 
 * \brief Compute required PLAINTEXT_2 length.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] cbor_items	Buffer containing the context_2.
 * \param sign_len		Size of the signature buffer in bytes.
 * \param[out] plaintext_2_len  On success, length of PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_plaintext_2_len(const struct edhoc_context *ctx,
				const struct cbor_items *cbor_items,
				size_t sign_len, size_t *plaintext_2_len);

/** 
 * \brief Prepare PLAINTEXT_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] cbor_items	Buffer containing the context_2.
 * \param[in] sign		Buffer containing the signature.
 * \param sign_len		Size of the \p sign buffer in bytes.
 * \param[out] ptxt	        Buffer where the generated plaintext is to be written.
 * \param ptxt_size		Size of the \p ptxt buffer in bytes.
 * \param[out] ptxt_len		On success, the number of bytes that make up the PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct cbor_items *cbor_items,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);

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
static int comp_keystream(const struct edhoc_context *ctx,
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
 * \brief Compute from cborised message 2 length of ciphertext 2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message 2.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[out] len		Length of ciphertext 2 in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_ciphertext_2_len(const struct edhoc_context *ctx,
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
 * \param[in] ptxt		Buffer containing the PLAINTEXT_2.
 * \param ptxt_len              Size of the \p plaintext buffer in bytes.
 * \param[out] parsed_ptxt     	Structure where parsed PLAINTEXT_2 is to be written.
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
 * \brief Compute transcript hash 3.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] cbor_items        Structure containing the context_2.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_2.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_th_3(struct edhoc_context *ctx,
		     const struct cbor_items *cbor_items, const uint8_t *ptxt,
		     size_t ptxt_len);

/**
 * \brief Perform compact encoding described in:
 *        - RFC 9528: 3.5.3.2. Compact Encoding of ID_CRED Fields for 'kid'.
 * 
 * \param[in] auth_cred         Authentication credentials.
 * \param[in,out] cbor_items    Structure containing the context_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int kid_compact_encoding(const struct edhoc_auth_creds *auth_cred,
				struct cbor_items *cbor_items);

/**
 * \brief Compute SALT_3e2m.
 * 
 * \param[in] ctx               EDHOC context.
 * \param[out] salt             Buffer where the generated salt is to be written.
 * \param salt_len              Size of the \p salt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len);

/**
 * \brief Compute G_RX for PRK_3e2m.
 * 
 * \param role                  EDHOC role.
 * \param[in,out] ctx           EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public key.
 * \param pub_key_len           Peer public key length.
 * \param[out] grx              Buffer where the generated G_RX is to be written.
 * \param grx_len               Size of the \p grx buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_grx(enum edhoc_role role, struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len, uint8_t *grx,
		    size_t grx_len);

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
	if (items < 24)
		return 1;
	if (items < 256)
		return 2;
	if (items < 65535)
		return 3;

	return 4;
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
	ret = ctx->keys.generate_key(ctx->user_ctx, EDHOC_KT_MAKE_KEY_PAIR,
				     NULL, 0, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	ctx->dh_pub_key_len = csuite.ecc_key_length;
	ctx->dh_priv_key_len = csuite.ecc_key_length;

	size_t pub_key_len = 0;
	size_t priv_key_len = 0;
	ret = ctx->crypto.make_key_pair(ctx->user_ctx, key_id, ctx->dh_priv_key,
					ctx->dh_priv_key_len, &priv_key_len,
					ctx->dh_pub_key, ctx->dh_pub_key_len,
					&pub_key_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || csuite.ecc_key_length != priv_key_len ||
	    csuite.ecc_key_length != pub_key_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int comp_dh_secret(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(ctx->user_ctx, EDHOC_KT_KEY_AGREEMENT,
				     ctx->dh_priv_key, ctx->dh_priv_key_len,
				     key_id);
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];
	ctx->dh_secret_len = csuite.ecc_key_length;

	size_t secret_len = 0;
	ret = ctx->crypto.key_agreement(ctx->user_ctx, key_id,
					ctx->dh_peer_pub_key,
					ctx->dh_peer_pub_key_len,
					ctx->dh_secret, ctx->dh_secret_len,
					&secret_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || secret_len != csuite.ecc_key_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int comp_th_2(struct edhoc_context *ctx, enum edhoc_role role)
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
	ret = ctx->crypto.hash(ctx->user_ctx, th_2, ARRAY_SIZE(th_2), ctx->th,
			       ctx->th_len, &hash_length);

	if (EDHOC_SUCCESS != ret || csuite.hash_length != hash_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_2;
	return EDHOC_SUCCESS;
}

static int comp_prk_2e(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	ctx->prk_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(ctx->user_ctx, EDHOC_KT_EXTRACT,
				     ctx->dh_secret, ctx->dh_secret_len,
				     key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	size_t out_len = 0;
	ret = ctx->crypto.extract(ctx->user_ctx, key_id, ctx->th, ctx->th_len,
				  ctx->prk, ctx->prk_len, &out_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->prk_state = EDHOC_PRK_STATE_2E;
	return EDHOC_SUCCESS;
}

static int comp_prk_3e2m(enum edhoc_role role, struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_2E != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	if (initiator == role) {
		switch (ctx->method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			ctx->prk_state = EDHOC_PRK_STATE_3E2M;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3: {
			const size_t hash_len =
				ctx->csuite[ctx->chosen_csuite_idx].hash_length;

			uint8_t salt_3e2m[hash_len];
			memset(salt_3e2m, 0, sizeof(salt_3e2m));

			int ret = comp_salt_3e2m(ctx, salt_3e2m,
						 ARRAY_SIZE(salt_3e2m));

			if (EDHOC_SUCCESS != ret)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			if (NULL != ctx->logger)
				ctx->logger(ctx->user_ctx, "SALT_3e2m",
					    salt_3e2m, ARRAY_SIZE(salt_3e2m));

			const size_t ecc_key_len =
				ctx->csuite[ctx->chosen_csuite_idx]
					.ecc_key_length;

			uint8_t grx[ecc_key_len];
			memset(grx, 0, sizeof(grx));

			ret = comp_grx(role, ctx, auth_cred, pub_key,
				       pub_key_len, grx, ARRAY_SIZE(grx));

			if (EDHOC_SUCCESS != ret)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			if (NULL != ctx->logger)
				ctx->logger(ctx->user_ctx, "G_RX", grx,
					    ARRAY_SIZE(grx));

			ctx->prk_len =
				ctx->csuite[ctx->chosen_csuite_idx].hash_length;

			uint8_t key_id[EDHOC_KID_LEN] = { 0 };
			ret = ctx->keys.generate_key(ctx->user_ctx,
						     EDHOC_KT_EXTRACT, grx,
						     ARRAY_SIZE(grx), key_id);
			memset(grx, 0, sizeof(grx));

			if (EDHOC_SUCCESS != ret)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			size_t out_len = 0;
			ret = ctx->crypto.extract(ctx->user_ctx, key_id,
						  salt_3e2m,
						  ARRAY_SIZE(salt_3e2m),
						  ctx->prk, ctx->prk_len,
						  &out_len);
			ctx->keys.destroy_key(ctx->user_ctx, key_id);

			if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			ctx->prk_state = EDHOC_PRK_STATE_3E2M;
			return EDHOC_SUCCESS;
		}

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	if (responder == role) {
		switch (ctx->method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			ctx->prk_state = EDHOC_PRK_STATE_3E2M;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3: {
			const size_t hash_len =
				ctx->csuite[ctx->chosen_csuite_idx].hash_length;

			uint8_t salt_3e2m[hash_len];
			memset(salt_3e2m, 0, sizeof(salt_3e2m));

			int ret = comp_salt_3e2m(ctx, salt_3e2m,
						 ARRAY_SIZE(salt_3e2m));

			if (EDHOC_SUCCESS != ret)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			if (NULL != ctx->logger)
				ctx->logger(ctx->user_ctx, "SALT_3e2m",
					    salt_3e2m, ARRAY_SIZE(salt_3e2m));

			const size_t ecc_key_len =
				ctx->csuite[ctx->chosen_csuite_idx]
					.ecc_key_length;

			uint8_t grx[ecc_key_len];
			memset(grx, 0, sizeof(grx));

			ret = comp_grx(role, ctx, auth_cred, pub_key,
				       pub_key_len, grx, ARRAY_SIZE(grx));

			if (EDHOC_SUCCESS != ret)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			if (NULL != ctx->logger)
				ctx->logger(ctx->user_ctx, "G_RX", grx,
					    ARRAY_SIZE(grx));

			ctx->prk_len =
				ctx->csuite[ctx->chosen_csuite_idx].hash_length;

			uint8_t key_id[EDHOC_KID_LEN] = { 0 };
			ret = ctx->keys.generate_key(ctx->user_ctx,
						     EDHOC_KT_EXTRACT, grx,
						     ARRAY_SIZE(grx), key_id);
			memset(grx, 0, sizeof(grx));

			if (EDHOC_SUCCESS != ret)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			size_t out_len = 0;
			ret = ctx->crypto.extract(ctx->user_ctx, key_id,
						  salt_3e2m,
						  ARRAY_SIZE(salt_3e2m),
						  ctx->prk, ctx->prk_len,
						  &out_len);
			ctx->keys.destroy_key(ctx->user_ctx, key_id);

			if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len)
				return EDHOC_ERROR_CRYPTO_FAILURE;

			ctx->prk_state = EDHOC_PRK_STATE_3E2M;
			return EDHOC_SUCCESS;
		}

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	return EDHOC_ERROR_NOT_PERMITTED;
}

static int comp_mac_2_input_len(const struct edhoc_context *ctx,
				const struct edhoc_auth_creds *auth_cred,
				enum edhoc_role role, size_t *context_2_len)
{
	if (NULL == ctx || NULL == auth_cred || NULL == context_2_len)
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
		for (size_t i = 0; i < auth_cred->x509_chain.nr_of_certs; ++i) {
			len += auth_cred->x509_chain.cert_len[i];
			len += cbor_bstr_overhead(
				auth_cred->x509_chain.cert_len[i]);
		}

		if (auth_cred->x509_chain.nr_of_certs > 1)
			len += cbor_array_overhead(
				auth_cred->x509_chain.nr_of_certs);

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

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t end_entity_idx =
			auth_cred->x509_chain.nr_of_certs - 1;
		len += auth_cred->x509_chain.cert_len[end_entity_idx];
		len += cbor_bstr_overhead(
			auth_cred->x509_chain.cert_len[end_entity_idx]);
		break;
	}

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

	*context_2_len = len;

	return EDHOC_SUCCESS;
}

static int gen_mac_2_context(const struct edhoc_context *ctx,
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

		for (size_t i = 0; i < auth_cred->x509_chain.nr_of_certs; ++i) {
			len += auth_cred->x509_chain.cert_len[i];
			len += cbor_bstr_overhead(
				auth_cred->x509_chain.cert_len[i]);
		}

		if (1 < auth_cred->x509_chain.nr_of_certs)
			len += cbor_array_overhead(
				auth_cred->x509_chain.nr_of_certs);

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

		break;

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		if (0 == auth_cred->x509_chain.nr_of_certs)
			return EDHOC_ERROR_BAD_STATE;

		cbor_id_cred_r._id_cred_x_x5chain_present = true;

		struct COSE_X509_ *cose_x509 =
			&cbor_id_cred_r._id_cred_x_x5chain._id_cred_x_x5chain;

		if (1 == auth_cred->x509_chain.nr_of_certs) {
			cose_x509->_COSE_X509_choice = _COSE_X509_bstr;
			cose_x509->_COSE_X509_bstr.value =
				auth_cred->x509_chain.cert[0];
			cose_x509->_COSE_X509_bstr.len =
				auth_cred->x509_chain.cert_len[0];
		} else {
			if (ARRAY_SIZE(cose_x509->_COSE_X509__certs_certs) <
			    auth_cred->x509_chain.nr_of_certs)
				return EDHOC_ERROR_BUFFER_TOO_SMALL;

			cose_x509->_COSE_X509_choice = _COSE_X509__certs;
			cose_x509->_COSE_X509__certs_certs_count =
				auth_cred->x509_chain.nr_of_certs;

			for (size_t i = 0;
			     i < auth_cred->x509_chain.nr_of_certs; ++i) {
				cose_x509->_COSE_X509__certs_certs[i].value =
					auth_cred->x509_chain.cert[i];
				cose_x509->_COSE_X509__certs_certs[i].len =
					auth_cred->x509_chain.cert_len[i];
			}
		}
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH: {
		cbor_id_cred_r._id_cred_x_x5t_present = true;

		struct COSE_CertHash *cose_x509 =
			&cbor_id_cred_r._id_cred_x_x5t._id_cred_x_x5t;

		cose_x509->_COSE_CertHash_hashValue.value =
			auth_cred->x509_hash.cert_fp;
		cose_x509->_COSE_CertHash_hashValue.len =
			auth_cred->x509_hash.cert_fp_len;

		switch (auth_cred->x509_hash.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			cose_x509->_COSE_CertHash_hashAlg_choice =
				_COSE_CertHash_hashAlg_int;
			cose_x509->_COSE_CertHash_hashAlg_int =
				auth_cred->x509_hash.alg_int;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			cose_x509->_COSE_CertHash_hashAlg_choice =
				_COSE_CertHash_hashAlg_tstr;
			cose_x509->_COSE_CertHash_hashAlg_tstr.value =
				auth_cred->x509_hash.alg_bstr;
			cose_x509->_COSE_CertHash_hashAlg_tstr.len =
				auth_cred->x509_hash.alg_bstr_length;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;
	}
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

	/* Check compact encoding of ID_CRED_R. */
	if (EDHOC_COSE_HEADER_KID == auth_cred->label) {
		ret = kid_compact_encoding(auth_cred, cbor_items);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;
	}

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

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t end_entity_idx =
			auth_cred->x509_chain.nr_of_certs - 1;
		len += auth_cred->x509_chain.cert_len[end_entity_idx];
		len += cbor_bstr_overhead(
			auth_cred->x509_chain.cert_len[end_entity_idx]);
		break;
	}

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

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t end_entity_idx =
			auth_cred->x509_chain.nr_of_certs - 1;
		cbor_cred_r.value = auth_cred->x509_chain.cert[end_entity_idx];
		cbor_cred_r.len =
			auth_cred->x509_chain.cert_len[end_entity_idx];
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH:
		cbor_cred_r.value = auth_cred->x509_hash.cert;
		cbor_cred_r.len = auth_cred->x509_hash.cert_len;
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (EDHOC_COSE_HEADER_KID == auth_cred->label &&
	    true == auth_cred->key_id.cred_is_cbor) {
		memcpy(cbor_items->cred_r, auth_cred->key_id.cred,
		       auth_cred->key_id.cred_len);
		cbor_items->cred_r_len = auth_cred->key_id.cred_len;
	} else {
		len = 0;
		ret = cbor_encode_byte_string_type_bstr_type(
			cbor_items->cred_r, cbor_items->cred_r_len,
			&cbor_cred_r, &len);

		if (ZCBOR_SUCCESS != ret || cbor_items->cred_r_len != len)
			return EDHOC_ERROR_CBOR_FAILURE;
	}

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

static int get_mac_2_len(enum edhoc_role role, const struct edhoc_context *ctx,
			 size_t *mac_2_len)
{
	if (NULL == ctx || NULL == mac_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	if (role == initiator) {
		switch (ctx->method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			*mac_2_len = csuite.hash_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
			*mac_2_len = csuite.mac_length;
			return EDHOC_SUCCESS;
		}
	}

	if (role == responder) {
		switch (ctx->method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			*mac_2_len = csuite.hash_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3:
			*mac_2_len = csuite.mac_length;
			return EDHOC_SUCCESS;
		}
	}

	return EDHOC_ERROR_NOT_PERMITTED;
}

static int comp_mac_2(const struct edhoc_context *ctx,
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
		._info_length = (uint32_t)mac_2_len,
	};

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_2);
	len += cbor_items->buf_len + cbor_bstr_overhead(cbor_items->buf_len);
	len += cbor_int_mem_req((int32_t)mac_2_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "MAC_2 info", info, len);

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				     ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, len, mac_2,
				 mac_2_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int comp_sign_or_mac_2_len(enum edhoc_role role,
				  const struct edhoc_context *ctx,
				  size_t *sign_or_mac_2_len)
{
	if (NULL == ctx || NULL == sign_or_mac_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	if (role == initiator) {
		switch (ctx->method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			*sign_or_mac_2_len = csuite.ecc_sign_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
			*sign_or_mac_2_len = csuite.mac_length;
			return EDHOC_SUCCESS;
		}
	}

	if (role == responder) {
		switch (ctx->method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			*sign_or_mac_2_len = csuite.ecc_sign_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3:
			*sign_or_mac_2_len = csuite.mac_length;
			return EDHOC_SUCCESS;
		}
	}

	return EDHOC_ERROR_NOT_PERMITTED;
}

static int comp_sign_or_mac_2(const struct edhoc_context *ctx,
			      const struct edhoc_auth_creds *auth_cred,
			      const struct cbor_items *cbor_items,
			      const uint8_t *mac_2, size_t mac_2_len,
			      uint8_t *sign, size_t sign_len)
{
	if (NULL == ctx || NULL == auth_cred || NULL == cbor_items ||
	    NULL == mac_2 || 0 == mac_2_len || NULL == sign || 0 == sign_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (ctx->method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_2: {
		const struct sig_structure cose_sign_1 = {
			._sig_structure_protected.value = cbor_items->id_cred_r,
			._sig_structure_protected.len =
				cbor_items->id_cred_r_len,
			._sig_structure_external_aad.value = cbor_items->th_2,
			._sig_structure_external_aad.len =
				cbor_items->th_2_len + cbor_items->cred_r_len +
				cbor_items->ead_2_len,
			._sig_structure_payload.value = mac_2,
			._sig_structure_payload.len = mac_2_len,
		};

		size_t len = 0;
		len += sizeof("Signature1") +
		       cbor_tstr_overhead(sizeof("Signature1"));
		len += cbor_items->id_cred_r_len +
		       cbor_bstr_overhead(cbor_items->id_cred_r_len);
		len += cbor_items->th_2_len + cbor_items->cred_r_len +
		       cbor_items->ead_2_len +
		       cbor_bstr_overhead(cbor_items->th_2_len +
					  cbor_items->cred_r_len +
					  cbor_items->ead_2_len);
		len += mac_2_len + cbor_int_mem_req((int32_t)mac_2_len);

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
		ret = ctx->crypto.signature(
			ctx->user_ctx, auth_cred->priv_key_id, cose_sign_1_buf,
			cose_sign_1_buf_len, sign, sign_len, &len);

		if (EDHOC_SUCCESS != ret || sign_len != len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_3:
		memcpy(sign, mac_2, mac_2_len);
		return EDHOC_SUCCESS;
	}

	return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;
}

static int comp_plaintext_2_len(const struct edhoc_context *ctx,
				const struct cbor_items *cbor_items,
				size_t sign_len, size_t *plaintext_2_len)
{
	if (NULL == ctx || NULL == cbor_items || 0 == sign_len ||
	    NULL == plaintext_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	size_t len = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		len += cbor_int_mem_req(ctx->cid.int_value);
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		len += ctx->cid.bstr_length;
		len += cbor_bstr_overhead(ctx->cid.bstr_length);
		break;
	}

	if (true == cbor_items->id_cred_r_is_comp_enc) {
		switch (cbor_items->id_cred_r_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			len += cbor_int_mem_req(cbor_items->id_cred_r_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			len += cbor_items->id_cred_r_bstr_len;
			len += cbor_bstr_overhead(
				cbor_items->id_cred_r_bstr_len);
			break;
		}
	} else {
		len += cbor_items->id_cred_r_len;
	}

	len += sign_len;
	len += cbor_bstr_overhead(sign_len);
	len += cbor_items->ead_2_len;

	*plaintext_2_len = len;
	return EDHOC_SUCCESS;
}

static int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct cbor_items *cbor_items,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t offset = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
		size_t len = 0;
		const int32_t value = ctx->cid.int_value;
		ret = cbor_encode_integer_type_int_type(
			ptxt, ptxt_size - offset, &value, &len);

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
			ptxt, ptxt_size - offset, &input, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		offset += len;
		break;
	}
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (cbor_items->id_cred_r_is_comp_enc) {
		switch (cbor_items->id_cred_r_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			memcpy(&ptxt[offset], &cbor_items->id_cred_r_int, 1);
			offset += 1;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			memcpy(&ptxt[offset], &cbor_items->id_cred_r_bstr,
			       cbor_items->id_cred_r_bstr_len);
			offset += cbor_items->id_cred_r_bstr_len;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
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
		&ptxt[offset], sign_len + cbor_bstr_overhead(sign_len) + 1,
		&cbor_sign_or_mac_2, &len);

	if (ZCBOR_SUCCESS != ret ||
	    (sign_len + cbor_bstr_overhead(sign_len)) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len;

	if (cbor_items->is_ead_2) {
		memcpy(&ptxt[offset], cbor_items->ead_2, cbor_items->ead_2_len);
		offset += cbor_items->ead_2_len;
	}

	if (offset > ptxt_size)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	*ptxt_len = offset;

	return EDHOC_SUCCESS;
}

static int comp_keystream(const struct edhoc_context *ctx,
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
		._info_length = (uint32_t)keystream_len,
	};

	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2);
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += cbor_int_mem_req((int32_t)keystream_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret || ARRAY_SIZE(info) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(ctx->user_ctx, EDHOC_KT_EXPAND, prk_2e,
				     prk_2e_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, ARRAY_SIZE(info),
				 keystream, keystream_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

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

static int comp_ciphertext_2_len(const struct edhoc_context *ctx,
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

			const struct COSE_X509_ *cose_x509 =
				&cbor_map->_map_x5chain._map_x5chain;

			switch (cose_x509->_COSE_X509_choice) {
			case _COSE_X509_bstr:
				parsed_ptxt->auth_cred.x509_chain.nr_of_certs =
					1;
				parsed_ptxt->auth_cred.x509_chain.cert[0] =
					cose_x509->_COSE_X509_bstr.value;
				parsed_ptxt->auth_cred.x509_chain.cert_len[0] =
					cose_x509->_COSE_X509_bstr.len;
				break;
			case _COSE_X509__certs: {
				if (ARRAY_SIZE(parsed_ptxt->auth_cred.x509_chain
						       .cert) <
				    cose_x509->_COSE_X509__certs_certs_count)
					return EDHOC_ERROR_BUFFER_TOO_SMALL;

				parsed_ptxt->auth_cred.x509_chain.nr_of_certs =
					cose_x509->_COSE_X509__certs_certs_count;

				for (size_t i = 0;
				     i <
				     cose_x509->_COSE_X509__certs_certs_count;
				     ++i) {
					parsed_ptxt->auth_cred.x509_chain
						.cert[i] =
						cose_x509
							->_COSE_X509__certs_certs
								[i]
							.value;
					parsed_ptxt->auth_cred.x509_chain
						.cert_len[i] =
						cose_x509
							->_COSE_X509__certs_certs
								[i]
							.len;
				}
				break;
			}

			default:
				return EDHOC_ERROR_NOT_PERMITTED;
			}
		}

		if (cbor_map->_map_x5t_present) {
			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_HASH;

			const struct COSE_CertHash *cose_x509 =
				&cbor_map->_map_x5t._map_x5t;

			parsed_ptxt->auth_cred.x509_hash.cert_fp =
				cose_x509->_COSE_CertHash_hashValue.value;
			parsed_ptxt->auth_cred.x509_hash.cert_fp_len =
				cose_x509->_COSE_CertHash_hashValue.len;

			switch (cose_x509->_COSE_CertHash_hashAlg_choice) {
			case _COSE_CertHash_hashAlg_int:
				parsed_ptxt->auth_cred.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_INTEGER;
				parsed_ptxt->auth_cred.x509_hash.alg_int =
					cose_x509->_COSE_CertHash_hashAlg_int;
				break;
			case _COSE_CertHash_hashAlg_tstr:
				if (ARRAY_SIZE(parsed_ptxt->auth_cred.x509_hash
						       .alg_bstr) <
				    cose_x509->_COSE_CertHash_hashAlg_tstr.len)
					return EDHOC_ERROR_BUFFER_TOO_SMALL;

				parsed_ptxt->auth_cred.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_BYTE_STRING;
				parsed_ptxt->auth_cred.x509_hash
					.alg_bstr_length =
					cose_x509->_COSE_CertHash_hashAlg_tstr
						.len;
				memcpy(parsed_ptxt->auth_cred.x509_hash.alg_bstr,
				       cose_x509->_COSE_CertHash_hashAlg_tstr
					       .value,
				       cose_x509->_COSE_CertHash_hashAlg_tstr
					       .len);
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

	switch (ctx->method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_1: {
		size_t len = 0;

		const struct sig_structure cose_sign_1 = {
			._sig_structure_protected.value = cbor_items->id_cred_r,
			._sig_structure_protected.len =
				cbor_items->id_cred_r_len,
			._sig_structure_external_aad.value = cbor_items->th_2,
			._sig_structure_external_aad.len =
				cbor_items->th_2_len + cbor_items->cred_r_len +
				cbor_items->ead_2_len,
			._sig_structure_payload.value = mac_2,
			._sig_structure_payload.len = mac_2_len,
		};

		len = 0;
		len += sizeof("Signature1") +
		       cbor_tstr_overhead(sizeof("Signature1"));
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
		ret = ctx->keys.generate_key(ctx->user_ctx, EDHOC_KT_VERIFY,
					     pub_key, pub_key_len, key_id);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		ret = ctx->crypto.verify(ctx->user_ctx, key_id, cose_sign_1_buf,
					 len, parsed_ptxt->sign_or_mac,
					 parsed_ptxt->sign_or_mac_len);
		ctx->keys.destroy_key(ctx->user_ctx, key_id);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	case EDHOC_METHOD_2:
	case EDHOC_METHOD_3: {
		if (mac_2_len != parsed_ptxt->sign_or_mac_len ||
		    0 != memcmp(parsed_ptxt->sign_or_mac, mac_2, mac_2_len))
			return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

		return EDHOC_SUCCESS;
	}

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}

static int comp_th_3(struct edhoc_context *ctx,
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
	ret = ctx->crypto.hash(ctx->user_ctx, th_3, ARRAY_SIZE(th_3), ctx->th,
			       ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_3;
	return EDHOC_SUCCESS;
}

static int kid_compact_encoding(const struct edhoc_auth_creds *auth_cred,
				struct cbor_items *cbor_items)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	cbor_items->id_cred_r_is_comp_enc = true;

	switch (auth_cred->key_id.encode_type) {
	case EDHOC_ENCODE_TYPE_INTEGER: {
		cbor_items->id_cred_r_enc_type = EDHOC_ENCODE_TYPE_INTEGER;
		if (true == auth_cred->key_id.cred_is_cbor) {
			cbor_items->id_cred_r_int =
				auth_cred->key_id.key_id_int;
		} else {
			len = 0;
			ret = cbor_encode_integer_type_int_type(
				(uint8_t *)&cbor_items->id_cred_r_int,
				sizeof(cbor_items->id_cred_r_int),
				&auth_cred->key_id.key_id_int, &len);

			if (ZCBOR_SUCCESS != ret)
				return EDHOC_ERROR_CBOR_FAILURE;
		}
		break;
	}

	case EDHOC_ENCODE_TYPE_BYTE_STRING: {
		cbor_items->id_cred_r_enc_type = EDHOC_ENCODE_TYPE_BYTE_STRING;

		if (true == auth_cred->key_id.cred_is_cbor) {
			if (1 == auth_cred->key_id.key_id_bstr_length) {
				int32_t val = auth_cred->key_id.key_id_bstr[0];
				int32_t result = 0;

				len = 0;
				ret = cbor_decode_integer_type_int_type(
					(uint8_t *)&val, sizeof(val), &result,
					&len);

				if (ZCBOR_SUCCESS != ret)
					return EDHOC_ERROR_CBOR_FAILURE;

				if (true == is_cbor_one_byte_int(result)) {
					cbor_items->id_cred_r_int = val;
					cbor_items->id_cred_r_enc_type =
						EDHOC_ENCODE_TYPE_INTEGER;
					break;
				}
			}

			cbor_items->id_cred_r_bstr_len =
				auth_cred->key_id.key_id_bstr_length;
			memcpy(cbor_items->id_cred_r_bstr,
			       auth_cred->key_id.key_id_bstr,
			       auth_cred->key_id.key_id_bstr_length);
		} else {
			const struct zcbor_string input = {
				.value = auth_cred->key_id.key_id_bstr,
				.len = auth_cred->key_id.key_id_bstr_length,
			};

			ret = cbor_encode_byte_string_type_bstr_type(
				cbor_items->id_cred_r_bstr,
				ARRAY_SIZE(cbor_items->id_cred_r_bstr) - 1,
				&input, &cbor_items->id_cred_r_bstr_len);

			if (ZCBOR_SUCCESS != ret)
				return EDHOC_ERROR_CBOR_FAILURE;
		}
		break;
	}
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

static int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_2E != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	const size_t hash_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	const struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M,
		._info_context.value = ctx->th,
		._info_context.len = ctx->th_len,
		._info_length = (uint32_t)hash_len,
	};

	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M);
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += cbor_int_mem_req((int32_t)hash_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret || ARRAY_SIZE(info) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				     ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, ARRAY_SIZE(info),
				 salt, salt_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int comp_grx(enum edhoc_role role, struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len, uint8_t *grx,
		    size_t grx_len)
{
	if (NULL == ctx || NULL == auth_cred || NULL == grx || 0 == grx_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (role) {
	case initiator: {
		uint8_t key_id[EDHOC_KID_LEN] = { 0 };
		ret = ctx->keys.generate_key(ctx->user_ctx,
					     EDHOC_KT_KEY_AGREEMENT,
					     ctx->dh_priv_key,
					     ctx->dh_priv_key_len, key_id);
		ctx->dh_priv_key_len = 0;
		memset(ctx->dh_priv_key, 0, ARRAY_SIZE(ctx->dh_priv_key));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx, key_id, pub_key,
						pub_key_len, grx, grx_len,
						&secret_len);

		ctx->keys.destroy_key(ctx->user_ctx, key_id);
		memset(key_id, 0, sizeof(key_id));

		if (EDHOC_SUCCESS != ret || secret_len != grx_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	case responder: {
		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx,
						auth_cred->priv_key_id,
						ctx->dh_peer_pub_key,
						ctx->dh_peer_pub_key_len, grx,
						grx_len, &secret_len);

		if (EDHOC_SUCCESS != ret || secret_len != grx_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 2:
 *	1.  Generate ephemeral Diffie-Hellmann key pair.
 *	2.  Compute Diffie-Hellmann shared secret.
 *	3.  Compute Transcript Hash 2 (TH_2).
 *	4a. Compute Pseudo Random Key 2 (PRK_2e).
 *      4b. Copy of Pseudo Random Key 2 for keystream (step 12).
 *	5.  Fetch authentication credentials.
 *      6.  Compose EAD_2 if present.
 *      7.  Compute psuedo random key (PRK_3e2m).
 *	8a. Compute required buffer length for context_2.
 *	8b. Cborise items required by context_2.
 *	8c. Compute Message Authentication Code (MAC_2).
 *	9.  Compute signature if needed (Signature_or_MAC_2).
 *	10. Prepare plaintext (PLAINTEXT_2).
 *	11. Compute key stream (KEYSTREAM_2).
 *      12. Compute Transcript Hash 3 (TH_3).
 *	13. Compute ciphertext (CIPHERTEXT_2).
 *	14. Cborise items for message 2.
 *      15. Clean-up EAD tokens.
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
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Generate ephemeral Diffie-Hellmann key pair. */
	ret = gen_dh_keys(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "G_Y", ctx->dh_pub_key,
			    ctx->dh_pub_key_len);
		ctx->logger(ctx->user_ctx, "Y", ctx->dh_priv_key,
			    ctx->dh_priv_key_len);
	}

	/* 2. Compute Diffie-Hellmann shared secret. */
	ret = comp_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 3. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx, responder);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 4a. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = comp_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 4b. Copy of Pseudo Random Key 2 for keystream (step 12). */
	uint8_t prk_2e[ctx->prk_len];
	memcpy(prk_2e, ctx->prk, sizeof(prk_2e));

	/* 5. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_cred = { 0 };
	ret = ctx->cred.fetch(ctx->user_ctx, &auth_cred);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/* 6. Compose EAD_2 if present. */
	if (NULL != ctx->ead.compose && 0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->ead.compose(ctx->user_ctx, EDHOC_MSG_2,
				       ctx->ead_token,
				       ARRAY_SIZE(ctx->ead_token) - 1,
				       &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens)
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;

		if (NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_2 compose label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_2 compose value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 7. Compute psuedo random key (PRK_3e2m). */
	ret = comp_prk_3e2m(responder, ctx, &auth_cred, NULL, 0);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_3e2m", ctx->prk, ctx->prk_len);

	/* 8a. Compute required buffer length for context_2. */
	size_t context_2_len = 0;
	ret = comp_mac_2_input_len(ctx, &auth_cred, responder, &context_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	uint8_t mac_2_content[sizeof(struct cbor_items) + context_2_len];
	memset(mac_2_content, 0, sizeof(mac_2_content));

	struct cbor_items *cbor_items = (struct cbor_items *)mac_2_content;
	cbor_items->buf_len = context_2_len;

	/* 8b. Cborise items required by context_2. */
	ret = gen_mac_2_context(ctx, &auth_cred, responder, cbor_items);

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
		ctx->logger(ctx->user_ctx, "context_2", cbor_items->buf,
			    cbor_items->buf_len);
	}

	/* 8c. Compute Message Authentication Code (MAC_2). */
	size_t mac_2_len = 0;
	ret = get_mac_2_len(responder, ctx, &mac_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	uint8_t mac_2[mac_2_len];
	memset(mac_2, 0, sizeof(mac_2));

	ret = comp_mac_2(ctx, cbor_items, mac_2, ARRAY_SIZE(mac_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "MAC_2", mac_2, ARRAY_SIZE(mac_2));

	/* 9. Compute signature if needed (Signature_or_MAC_2). */
	size_t sign_or_mac_len = 0;
	ret = comp_sign_or_mac_2_len(responder, ctx, &sign_or_mac_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

	uint8_t sign_or_mac[sign_or_mac_len];
	memset(sign_or_mac, 0, sizeof(sign_or_mac));

	ret = comp_sign_or_mac_2(ctx, &auth_cred, cbor_items, mac_2,
				 ARRAY_SIZE(mac_2), sign_or_mac,
				 ARRAY_SIZE(sign_or_mac));
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "Signature_or_MAC_2", sign_or_mac,
			    ARRAY_SIZE(sign_or_mac));

	/* 10. Prepare plaintext (PLAINTEXT_2). */
	size_t plaintext_len = 0;
	ret = comp_plaintext_2_len(ctx, cbor_items, ARRAY_SIZE(sign_or_mac),
				   &plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	uint8_t plaintext[plaintext_len];
	memset(plaintext, 0, sizeof(plaintext));

	plaintext_len = 0;
	ret = prepare_plaintext_2(ctx, cbor_items, sign_or_mac,
				  ARRAY_SIZE(sign_or_mac), plaintext,
				  ARRAY_SIZE(plaintext), &plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_2", plaintext,
			    plaintext_len);

	/* 11. Compute key stream (KEYSTREAM_2). */
	uint8_t keystream[plaintext_len];
	memset(keystream, 0, sizeof(keystream));

	ret = comp_keystream(ctx, prk_2e, ARRAY_SIZE(prk_2e), keystream,
			     ARRAY_SIZE(keystream));
	memset(prk_2e, 0, sizeof(prk_2e));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "KEYSTREAM_2", keystream,
			    ARRAY_SIZE(keystream));

	/* 12. Compute Transcript Hash 3 (TH_3). */
	ret = comp_th_3(ctx, cbor_items, plaintext, plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 13. Compute ciphertext (CIPHERTEXT_2). */
	xor_arrays(plaintext, keystream, plaintext_len);
	const uint8_t *ciphertext = plaintext;
	const size_t ciphertext_len = plaintext_len;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_2", ciphertext,
			    ciphertext_len);

	/* 14. Cborise items for message 2. */
	ret = prepare_message_2(ctx, ciphertext, ciphertext_len, msg_2,
				msg_2_size, msg_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "message_2", msg_2, *msg_2_len);

	/* 15. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_WAIT_M3;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
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
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* 1. Compute required length for ciphertext. */
	ret = comp_ciphertext_2_len(ctx, msg_2, msg_2_len, &len);

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
	ret = comp_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx, initiator);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = comp_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 6. Compute key stream (KEYSTREAM_2). */
	uint8_t keystream[ARRAY_SIZE(ciphertext_2)];
	memset(keystream, 0, sizeof(keystream));

	ret = comp_keystream(ctx, ctx->prk, ctx->prk_len, keystream,
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

		if (NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_2 process label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_2 process value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 10. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;

	ret = ctx->cred.verify(ctx->user_ctx, &parsed_ptxt.auth_cred, &pub_key,
			       &pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 11. Compute psuedo random key (PRK_3e2m). */
	ret = comp_prk_3e2m(initiator, ctx, &parsed_ptxt.auth_cred, pub_key,
			    pub_key_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_3e2m", ctx->prk, ctx->prk_len);

	/* 12. Compute required buffer length for context_2. */
	size_t context_2_len = 0;
	ret = comp_mac_2_input_len(ctx, &parsed_ptxt.auth_cred, initiator,
				   &context_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	uint8_t mac_2_content[sizeof(struct cbor_items) + context_2_len];
	memset(mac_2_content, 0, sizeof(mac_2_content));

	struct cbor_items *cbor_items = (struct cbor_items *)mac_2_content;
	cbor_items->buf_len = context_2_len;

	/* 13. Cborise items required by context_2. */
	ret = gen_mac_2_context(ctx, &parsed_ptxt.auth_cred, initiator,
				cbor_items);

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
		ctx->logger(ctx->user_ctx, "context_2", cbor_items->buf,
			    cbor_items->buf_len);
	}

	/* 14. Compute Message Authentication Code (MAC_2). */
	size_t mac_2_len = 0;
	ret = get_mac_2_len(initiator, ctx, &mac_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	uint8_t mac_2[mac_2_len];
	memset(mac_2, 0, sizeof(mac_2));

	ret = comp_mac_2(ctx, cbor_items, mac_2, ARRAY_SIZE(mac_2));

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
	ret = comp_th_3(ctx, cbor_items, plaintext, plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 17. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
