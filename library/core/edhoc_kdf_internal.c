/**
 * \file    edhoc_kdf_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC key derivation function implementation.
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
#include <edhoc/values.h>
#include <edhoc/crypto.h>

/* EDHOC internal headers: */
#include "edhoc_kdf_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_edhoc_types.h>
#include <backend_cbor_info_encode.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/** Which crypto backend entry point consumes the derived keying material. */
enum expand_output {
	/** \ref edhoc_crypto.expand, producing a key handle. */
	EXPAND_OUTPUT_KEY,
	/** \ref edhoc_crypto.expand_raw, producing bytes. */
	EXPAND_OUTPUT_RAW,
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Number of bytes the CBOR encoding of an info triple occupies.
 *
 * \param label                 Info label.
 * \param context_length        Size of the info context in bytes.
 * \param output_length         Requested output length in bytes.
 *
 * \return Exact encoded size.
 */
STATIC size_t comp_info_length(int32_t label, size_t context_length,
			       size_t output_length);

/**
 * \brief CBOR-encode an info triple.
 *
 * \param[out] info             Buffer receiving the encoding.
 * \param info_size             Size of the \p info buffer in bytes.
 * \param label                 Info label.
 * \param[in] context           Info context.
 * \param context_length        Size of the \p context buffer in bytes.
 * \param output_length         Requested output length in bytes.
 * \param[out] info_length      On success, number of bytes written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int encode_info(uint8_t *info, size_t info_size, int32_t label,
		       const uint8_t *context, size_t context_length,
		       size_t output_length, size_t *info_length);

/**
 * \brief Encode the info triple and run EDHOC_Expand over it.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] prk_key_id        Pseudorandom key handle.
 * \param label                 Info label.
 * \param[in] context           Info context.
 * \param context_length        Size of the \p context buffer in bytes.
 * \param kind                  Which backend entry point to call.
 * \param usage                 Policy of the produced key; unused for
 *                              \ref EXPAND_OUTPUT_RAW.
 * \param[out] output           Key handle buffer or raw output buffer.
 * \param output_length         Requested output length in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_expand(const struct edhoc_context *ctx, const void *prk_key_id,
		       int32_t label, const uint8_t *context,
		       size_t context_length, enum expand_output kind,
		       enum edhoc_key_usage usage, void *output,
		       size_t output_length);

/* Static function definitions --------------------------------------------- */

STATIC size_t comp_info_length(int32_t label, size_t context_length,
			       size_t output_length)
{
	return edhoc_cbor_int_head_length(label) + context_length +
	       edhoc_cbor_bstr_head_length(context_length) +
	       edhoc_cbor_int_head_length((int32_t)output_length);
}

STATIC int encode_info(uint8_t *info, size_t info_size, int32_t label,
		       const uint8_t *context, size_t context_length,
		       size_t output_length, size_t *info_length)
{
	const struct info input_info = {
		.info_label = label,
		.info_context.value = context,
		.info_context.len = context_length,
		.info_length = (uint32_t)output_length,
	};

	const int ret =
		cbor_encode_info(info, info_size, &input_info, info_length);

	if (ZCBOR_SUCCESS != ret || info_size != *info_length) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_expand(const struct edhoc_context *ctx, const void *prk_key_id,
		       int32_t label, const uint8_t *context,
		       size_t context_length, enum expand_output kind,
		       enum edhoc_key_usage usage, void *output,
		       size_t output_length)
{
	EDHOC_MEM_ALLOC(uint8_t, info,
			comp_info_length(label, context_length, output_length));

	if (NULL == info) {
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t info_length = 0;
	int ret = encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), label, context,
			      context_length, output_length, &info_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(info);
		return ret;
	}

	switch (kind) {
	case EXPAND_OUTPUT_KEY:
		ret = edhoc_crypto(ctx)->expand(ctx->user_context, prk_key_id,
						info, info_length, usage,
						output);
		break;
	case EXPAND_OUTPUT_RAW:
		ret = edhoc_crypto(ctx)->expand_raw(ctx->user_context,
						    prk_key_id, info,
						    info_length, output,
						    output_length);
		break;
	default:
		ret = EDHOC_ERROR_NOT_SUPPORTED;
		break;
	}

	EDHOC_LOG_HEXDUMP_DBG(info, info_length, "EDHOC_KDF info");
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_kdf_extract(struct edhoc_context *ctx, const void *ikm_key_id,
		      const uint8_t *salt, size_t salt_length,
		      enum edhoc_key_slot_id output_slot)
{
	if (NULL == ctx || NULL == ikm_key_id || NULL == salt ||
	    0 == salt_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const int ret = edhoc_crypto(ctx)->extract(
		ctx->user_context, ikm_key_id, salt, salt_length,
		edhoc_key_slot_id_mut(ctx, output_slot));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Extract into key slot %d: %d", (int)output_slot,
			      ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, output_slot);

	return EDHOC_SUCCESS;
}

int edhoc_kdf_expand(const struct edhoc_context *ctx, const void *prk_key_id,
		     int32_t label, const uint8_t *context,
		     size_t context_length, enum edhoc_key_usage usage,
		     void *output_key_id, size_t output_length)
{
	if (NULL == ctx || NULL == prk_key_id ||
	    (NULL == context && 0 != context_length) || NULL == output_key_id ||
	    0 == output_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const int ret = comp_expand(ctx, prk_key_id, label, context,
				    context_length, EXPAND_OUTPUT_KEY, usage,
				    output_key_id, output_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand key, label %d: %d", (int)label, ret);
		return ret;
	}

	return EDHOC_SUCCESS;
}

int edhoc_kdf_expand_raw(const struct edhoc_context *ctx,
			 const void *prk_key_id, int32_t label,
			 const uint8_t *context, size_t context_length,
			 uint8_t *output, size_t output_length)
{
	if (NULL == ctx || NULL == prk_key_id ||
	    (NULL == context && 0 != context_length) || NULL == output ||
	    0 == output_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const int ret = comp_expand(ctx, prk_key_id, label, context,
				    context_length, EXPAND_OUTPUT_RAW,
				    EDHOC_KEY_USAGE_KDF, output, output_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand raw, label %d: %d", (int)label, ret);
		return ret;
	}

	return EDHOC_SUCCESS;
}
