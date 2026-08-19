/**
 * \file    edhoc_plaintext_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC plaintext implementation.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC public headers: */
#include <edhoc/types.h>
#include <edhoc/values.h>

/* EDHOC internal headers: */
#include "edhoc_plaintext_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_ead_internal.h"
#include "edhoc_mac_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_credentials_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_types.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_plaintext_2_decode.h>
#include <backend_cbor_plaintext_3_decode.h>
#include <backend_cbor_plaintext_4_encode.h>
#include <backend_cbor_plaintext_4_decode.h>

/* Standard library headers: */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Number of bytes PLAINTEXT_2 or PLAINTEXT_3 occupies once encoded.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] input             Plaintext to measure.
 * \param[out] length           On success, the encoded size.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int length_classic_2_3(const struct edhoc_context *ctx,
			      const struct edhoc_plaintext_input *input,
			      size_t *length);

/**
 * \brief Assemble PLAINTEXT_2 or PLAINTEXT_3.
 *
 *        The two share every item but C_R, which only PLAINTEXT_2 carries.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] input             Plaintext to assemble.
 * \param[out] ptxt             Buffer for the plaintext.
 * \param ptxt_size             Size of the \p ptxt buffer in bytes.
 * \param[out] ptxt_len         On success, number of bytes written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compose_classic_2_3(const struct edhoc_context *ctx,
			       const struct edhoc_plaintext_input *input,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);

/**
 * \brief Assemble PLAINTEXT_4.
 *
 * \param[in] ctx               EDHOC context.
 * \param[out] ptxt             Buffer for the plaintext.
 * \param ptxt_size             Size of the \p ptxt buffer in bytes.
 * \param[out] ptxt_len         On success, number of bytes written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compose_classic_4(const struct edhoc_context *ctx, uint8_t *ptxt,
			     size_t ptxt_size, size_t *ptxt_len);

/**
 * \brief Decode PLAINTEXT_2.
 *
 *        PLAINTEXT_2 and PLAINTEXT_3 are decoded separately because the
 *        generator gave them distinct structures and field names; keeping a
 *        decoder per structure avoids holding both on the stack.
 *
 * \param[in,out] ctx           EDHOC context.
 * \param[in] ptxt              Plaintext to decode.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] parsed           On success, the decoded items.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_classic_2(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed);

/**
 * \brief Decode PLAINTEXT_3.
 *
 * \param[in,out] ctx           EDHOC context.
 * \param[in] ptxt              Plaintext to decode.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] parsed           On success, the decoded items.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_classic_3(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed);

/**
 * \brief Decode PLAINTEXT_4 and take its EAD items into the context.
 *
 * \param[in,out] ctx           EDHOC context.
 * \param[in] ptxt              Plaintext to decode.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_classic_4(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len);

/* Static function definitions --------------------------------------------- */

STATIC int length_classic_2_3(const struct edhoc_context *ctx,
			      const struct edhoc_plaintext_input *input,
			      size_t *length)
{
	const struct mac_context *mac_ctx = input->mac_context;
	size_t len = 0;

	if (EDHOC_PLAINTEXT_CLASSIC_2 == input->id) {
		len += edhoc_connection_id_encoded_length(
			&ctx->negotiation.connection_id);
	}

	len += (0 != mac_ctx->id_cred_comp_len) ? mac_ctx->id_cred_comp_len :
						  mac_ctx->id_cred_len;

	len += input->signature_length;
	len += edhoc_cbor_bstr_head_length(input->signature_length);
	len += mac_ctx->ead_len;

	*length = len;

	return EDHOC_SUCCESS;
}

STATIC int compose_classic_2_3(const struct edhoc_context *ctx,
			       const struct edhoc_plaintext_input *input,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len)
{
	const struct mac_context *mac_ctx = input->mac_context;
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t offset = 0;

	if (EDHOC_PLAINTEXT_CLASSIC_2 == input->id) {
		ret = edhoc_connection_id_encode(
			&ctx->negotiation.connection_id, ptxt, ptxt_size,
			&offset);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}
	}

	const size_t id_cred_len = (0 != mac_ctx->id_cred_comp_len) ?
					   mac_ctx->id_cred_comp_len :
					   mac_ctx->id_cred_len;
	const uint8_t *id_cred = (0 != mac_ctx->id_cred_comp_len) ?
					 mac_ctx->id_cred_comp :
					 mac_ctx->id_cred;

	memcpy(&ptxt[offset], id_cred, id_cred_len);
	offset += id_cred_len;

	const struct zcbor_string cbor_sign_or_mac = {
		.value = input->signature,
		.len = input->signature_length,
	};

	size_t len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&ptxt[offset],
		input->signature_length +
			edhoc_cbor_bstr_head_length(input->signature_length),
		&cbor_sign_or_mac, &len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	offset += len;

	if (mac_ctx->is_ead) {
		memcpy(&ptxt[offset], mac_ctx->ead, mac_ctx->ead_len);
		offset += mac_ctx->ead_len;
	}

	if (offset > ptxt_size) {
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*ptxt_len = offset;

	return EDHOC_SUCCESS;
}

STATIC int compose_classic_4(const struct edhoc_context *ctx, uint8_t *ptxt,
			     size_t ptxt_size, size_t *ptxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct plaintext_4 ead_4 = { .plaintext_4_present = false };

	if (edhoc_ead_is_present(ctx)) {
		ead_4.plaintext_4_present = true;

		ret = edhoc_ead_tokens_encode(ctx, &ead_4.plaintext_4);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}
	}

	ret = cbor_encode_plaintext_4(ptxt, ptxt_size, &ead_4, ptxt_len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_classic_2(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed)
{
	size_t len = 0;
	struct plaintext_2 cbor_ptxt_2 = { 0 };
	int ret = cbor_decode_plaintext_2(ptxt, ptxt_len, &cbor_ptxt_2, &len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	switch (cbor_ptxt_2.plaintext_2_C_R_choice) {
	case plaintext_2_C_R_int_c:
		ret = edhoc_connection_id_from_int(
			cbor_ptxt_2.plaintext_2_C_R_int,
			&ctx->negotiation.peer_connection_id);
		break;

	case plaintext_2_C_R_bstr_c:
		ret = edhoc_connection_id_from_bstr(
			cbor_ptxt_2.plaintext_2_C_R_bstr.value,
			cbor_ptxt_2.plaintext_2_C_R_bstr.len,
			&ctx->negotiation.peer_connection_id);
		break;

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	switch (cbor_ptxt_2.plaintext_2_ID_CRED_R_choice) {
	case plaintext_2_ID_CRED_R_int_c:
		ret = edhoc_credential_parse_kid_int(
			cbor_ptxt_2.plaintext_2_ID_CRED_R_int,
			&parsed->kid_byte, &parsed->peer_credential_id);
		break;

	case plaintext_2_ID_CRED_R_bstr_c:
		ret = edhoc_credential_parse_kid_bstr(
			cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.value,
			cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.len,
			&parsed->peer_credential_id);
		break;

	case plaintext_2_ID_CRED_R_id_cred_x_m_c:
		ret = edhoc_credential_parse_map(
			&cbor_ptxt_2.plaintext_2_ID_CRED_R_id_cred_x_m,
			&parsed->peer_credential_id);
		break;

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	parsed->sign_or_mac.value =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.value;
	parsed->sign_or_mac.length =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.len;

	if (cbor_ptxt_2.plaintext_2_ead_m_present) {
		return edhoc_ead_tokens_decode(ctx,
					       &cbor_ptxt_2.plaintext_2_ead_m);
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_classic_3(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed)
{
	size_t len = 0;
	struct plaintext_3 cbor_ptxt_3 = { 0 };
	int ret = cbor_decode_plaintext_3(ptxt, ptxt_len, &cbor_ptxt_3, &len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	switch (cbor_ptxt_3.plaintext_3_ID_CRED_I_choice) {
	case plaintext_3_ID_CRED_I_int_c:
		ret = edhoc_credential_parse_kid_int(
			cbor_ptxt_3.plaintext_3_ID_CRED_I_int,
			&parsed->kid_byte, &parsed->peer_credential_id);
		break;

	case plaintext_3_ID_CRED_I_bstr_c:
		ret = edhoc_credential_parse_kid_bstr(
			cbor_ptxt_3.plaintext_3_ID_CRED_I_bstr.value,
			cbor_ptxt_3.plaintext_3_ID_CRED_I_bstr.len,
			&parsed->peer_credential_id);
		break;

	case plaintext_3_ID_CRED_I_id_cred_x_m_c:
		ret = edhoc_credential_parse_map(
			&cbor_ptxt_3.plaintext_3_ID_CRED_I_id_cred_x_m,
			&parsed->peer_credential_id);
		break;

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	parsed->sign_or_mac.value =
		cbor_ptxt_3.plaintext_3_Signature_or_MAC_3.value;
	parsed->sign_or_mac.length =
		cbor_ptxt_3.plaintext_3_Signature_or_MAC_3.len;

	if (cbor_ptxt_3.plaintext_3_ead_m_present) {
		return edhoc_ead_tokens_decode(ctx,
					       &cbor_ptxt_3.plaintext_3_ead_m);
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_classic_4(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len)
{
	size_t len = 0;
	struct plaintext_4 ead_4 = { 0 };
	const int ret = cbor_decode_plaintext_4(ptxt, ptxt_len, &ead_4, &len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return edhoc_ead_tokens_decode(ctx, &ead_4.plaintext_4);
}

/* Module interface function definitions ----------------------------------- */

int edhoc_plaintext_length(const struct edhoc_context *ctx,
			   const struct edhoc_plaintext_input *input,
			   size_t *length)
{
	if (NULL == ctx || NULL == input || NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (input->id) {
	case EDHOC_PLAINTEXT_CLASSIC_2:
	case EDHOC_PLAINTEXT_CLASSIC_3:
		if (NULL == input->mac_context ||
		    0 == input->signature_length) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		ret = length_classic_2_3(ctx, input, length);
		break;

	case EDHOC_PLAINTEXT_CLASSIC_4:
		/* PLAINTEXT_4 is its EAD and nothing else. */
		ret = edhoc_ead_encoded_length(ctx, length);
		break;

	default:
		EDHOC_LOG_ERR("Invalid plaintext: %d", input->id);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Plaintext %d length: %d", input->id, ret);
	}

	return ret;
}

int edhoc_plaintext_compose(const struct edhoc_context *ctx,
			    const struct edhoc_plaintext_input *input,
			    uint8_t *plaintext, size_t plaintext_size,
			    size_t *plaintext_length)
{
	if (NULL == ctx || NULL == input || NULL == plaintext ||
	    0 == plaintext_size || NULL == plaintext_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (input->id) {
	case EDHOC_PLAINTEXT_CLASSIC_2:
	case EDHOC_PLAINTEXT_CLASSIC_3:
		if (NULL == input->mac_context || NULL == input->signature ||
		    0 == input->signature_length) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		ret = compose_classic_2_3(ctx, input, plaintext, plaintext_size,
					  plaintext_length);
		break;

	case EDHOC_PLAINTEXT_CLASSIC_4:
		ret = compose_classic_4(ctx, plaintext, plaintext_size,
					plaintext_length);
		break;

	default:
		EDHOC_LOG_ERR("Invalid plaintext: %d", input->id);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Plaintext %d compose: %d", input->id, ret);
	}

	return ret;
}

int edhoc_plaintext_parse(struct edhoc_context *ctx, enum edhoc_plaintext_id id,
			  const uint8_t *plaintext, size_t plaintext_length,
			  struct plaintext *parsed)
{
	if (NULL == ctx || NULL == plaintext) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (id) {
	case EDHOC_PLAINTEXT_CLASSIC_2:
		if (0 == plaintext_length || NULL == parsed) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		ret = parse_classic_2(ctx, plaintext, plaintext_length, parsed);
		break;

	case EDHOC_PLAINTEXT_CLASSIC_3:
		if (0 == plaintext_length || NULL == parsed) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		ret = parse_classic_3(ctx, plaintext, plaintext_length, parsed);
		break;

	case EDHOC_PLAINTEXT_CLASSIC_4:
		/* PLAINTEXT_4 is empty when message 4 carries no EAD_4. */
		ret = parse_classic_4(ctx, plaintext, plaintext_length);
		break;

	default:
		EDHOC_LOG_ERR("Invalid plaintext: %d", id);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Plaintext %d parse: %d", id, ret);
	}

	return ret;
}
