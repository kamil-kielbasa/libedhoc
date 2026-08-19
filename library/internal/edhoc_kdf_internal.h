/**
 * \file    edhoc_kdf_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC key derivation function (RFC 9528: 4.1.2).
 *
 *          EDHOC_KDF is EDHOC_Expand over a CBOR-encoded \c info triple
 *          (label, context, length). Every derived value in the protocol goes
 *          through it, so the encoding lives here once and callers only name
 *          the label and hand over the context.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_KDF_INTERNAL_H
#define EDHOC_KDF_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* EDHOC public headers: */
#include <edhoc/crypto.h>

/* EDHOC internal headers: */
#include "edhoc_key_slot_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-kdf-types EDHOC KDF types
 * @{
 */

/** EDHOC context, defined by \c edhoc_context_internal.h. */
struct edhoc_context;

/**
 * \brief EDHOC_KDF info labels.
 */
enum edhoc_kdf_label {
	/** KEYSTREAM_2 (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_KEYSTREAM_2 = 0,
	/** SALT_3e2m (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_SALT_3E2M = 1,
	/** MAC_2 (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_MAC_2 = 2,
	/** K_3 (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_K_3 = 3,
	/** IV_3 (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_IV_3 = 4,
	/** SALT_4e3m (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_SALT_4E3M = 5,
	/** MAC_3 (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_MAC_3 = 6,
	/** PRK_out (RFC 9528: 4.1.3). */
	EDHOC_KDF_LABEL_PRK_OUT = 7,
	/** K_4 (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_K_4 = 8,
	/** IV_4 (RFC 9528: 4.1.2). */
	EDHOC_KDF_LABEL_IV_4 = 9,
	/** PRK_exporter (RFC 9528: 4.2.1). */
	EDHOC_KDF_LABEL_PRK_EXPORTER = 10,
	/** New PRK_out for KeyUpdate (RFC 9528: 4.1.3). */
	EDHOC_KDF_LABEL_NEW_PRK_OUT = 11,
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-kdf EDHOC key derivation
 * @{
 */

/**
 * \brief EDHOC_Extract (RFC 9528: 4.1.1) into a context key slot.
 *
 *        Marks \p output_slot live on success.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param[in] ikm_key_id                Input keying material handle.
 * \param[in] salt                      Salt bytes.
 * \param salt_length                   Size of the \p salt buffer in bytes.
 * \param output_slot                   Key slot receiving the pseudorandom key.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_kdf_extract(struct edhoc_context *ctx, const void *ikm_key_id,
		      const uint8_t *salt, size_t salt_length,
		      enum edhoc_key_slot_id output_slot);

/**
 * \brief EDHOC_KDF producing a key handle (RFC 9528: 4.1.2).
 *
 * \param[in] ctx                       EDHOC context.
 * \param[in] prk_key_id                Pseudorandom key handle.
 * \param label                         Info label: an \ref edhoc_kdf_label
 *                                      constant, or an application exporter
 *                                      label the caller has already validated.
 * \param[in] context                   Info context; NULL only together with a
 *                                      zero \p context_length.
 * \param context_length                Size of the \p context buffer in bytes.
 * \param usage                         Policy of the produced key.
 * \param[out] output_key_id            Buffer receiving the key handle.
 * \param output_length                 Requested key length in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_kdf_expand(const struct edhoc_context *ctx, const void *prk_key_id,
		     int32_t label, const uint8_t *context,
		     size_t context_length, enum edhoc_key_usage usage,
		     void *output_key_id, size_t output_length);

/**
 * \brief EDHOC_KDF producing raw output (RFC 9528: 4.1.2).
 *
 * \param[in] ctx                       EDHOC context.
 * \param[in] prk_key_id                Pseudorandom key handle.
 * \param label                         Info label: an \ref edhoc_kdf_label
 *                                      constant, or an application exporter
 *                                      label the caller has already validated.
 * \param[in] context                   Info context; NULL only together with a
 *                                      zero \p context_length.
 * \param context_length                Size of the \p context buffer in bytes.
 * \param[out] output                   Buffer receiving the keying material.
 * \param output_length                 Requested output length in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_kdf_expand_raw(const struct edhoc_context *ctx,
			 const void *prk_key_id, int32_t label,
			 const uint8_t *context, size_t context_length,
			 uint8_t *output, size_t output_length);

/**@}*/

#endif /* EDHOC_KDF_INTERNAL_H */
