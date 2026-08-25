/**
 * \file    edhoc_mac_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC MAC context, MAC and Signature_or_MAC (RFC 9528: 5.3.2, 5.4.2).
 *
 *          Which of the two forms a message carries follows from the method
 *          and the message number alone, so that mapping lives in one place
 *          here and every entry point reads it from there.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_MAC_INTERNAL_H
#define EDHOC_MAC_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* EDHOC public headers: */
#include <edhoc/types.h>
#include <edhoc/ead.h>
#include <edhoc/credentials.h>

/* EDHOC internal headers: */
#include "edhoc_context_internal.h"
#include "edhoc_credentials_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-mac-types EDHOC MAC types
 * @{
 */

/**
 * \brief RFC 9528:
 *        - 5.3.2. Responder Composition of Message 2.
 *          - context_2.
 *        - 5.4.2. Initiator Composition of Message 3.
 *          - context_3.
 */
struct mac_context {
	/** Buffer containing cborised connection identifier. */
	uint8_t *conn_id;
	/** Size of the \p conn_id buffer in bytes. */
	size_t conn_id_len;

	/** Buffer containing cborised credentials identifier. */
	uint8_t *id_cred;
	/** Size of the \p id_cred buffer in bytes. */
	size_t id_cred_len;

	/** Compact ID_CRED (RFC 9528: 3.5.3.2), already CBOR-encoded: a one byte
	 *  integer, or a byte string with its header. Empty when the credential
	 *  is not eligible for the compact encoding. */
	uint8_t id_cred_comp[EDHOC_CREDENTIAL_KID_COMPACT_MAX_LEN];
	/** Number of valid bytes in \p id_cred_comp. */
	size_t id_cred_comp_len;

	/** Buffer containing cborised transcript hash. */
	uint8_t *th;
	/** Size of the \p th buffer in bytes. */
	size_t th_len;

	/** Buffer containing cborised credentials. */
	uint8_t *cred;
	/** Size of the \p cred buffer in bytes. */
	size_t cred_len;

	/** Is EAD attached? */
	bool is_ead;
	/** Buffer containing cborised EAD. */
	uint8_t *ead;
	/** Size of the \p ead buffer in bytes. */
	size_t ead_len;

	/** Size of the \p buf buffer in bytes. */
	size_t buf_len;
	/** Flexible array member buffer. */
	uint8_t buf[];
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-mac-context EDHOC MAC context
 * @{
 */

/**
 * \brief Compute required buffer length for MAC 2/3 context.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] credential_material       ID_CRED_x and CRED_x encoder input.
 * \param[out] mac_context_length       On success, number of bytes that make up MAC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_mac_context_length(
	const struct edhoc_context *edhoc_context,
	const struct edhoc_credential_material_asymmetric *credential_material,
	size_t *mac_context_length);

/**
 * \brief CBOR-encode items required by the MAC 2/3 context.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] credential_material       ID_CRED_x and CRED_x encoder input.
 * \param[out] mac_context              On success, generated MAC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_mac_context_compose(
	const struct edhoc_context *edhoc_context,
	const struct edhoc_credential_material_asymmetric *credential_material,
	struct mac_context *mac_context);

/**@}*/

/** \defgroup edhoc-sign-or-mac EDHOC Signature_or_MAC
 * @{
 */

/**
 * \brief Compute required buffer length for MAC 2/3.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] mac_length               On success, number of bytes that make up
 *                                      MAC 2/3 length requirements.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_mac_length(const struct edhoc_context *edhoc_context,
		     size_t *mac_length);

/**
 * \brief Compute MAC 2/3 buffer.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] mac_context               MAC context.
 * \param[out] mac                      Buffer where the generated MAC 2/3 is to be written.
 * \param mac_length                    Size of the \p mac buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_mac_compute(const struct edhoc_context *edhoc_context,
		      const struct mac_context *mac_context, uint8_t *mac,
		      size_t mac_length);

/**
 * \brief Compute required buffer length for Signature_or_MAC 2/3.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] sign_or_mac_length       On success, number of bytes that make up
 *                                      Signature_or_MAC 2/3 length requirements.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_sign_or_mac_length(const struct edhoc_context *edhoc_context,
			     size_t *sign_or_mac_length);

/**
 * \brief Compute Signature_or_MAC 2/3 buffer.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] private_key_id            Handle of the local private key.
 * \param[in] mac_context               MAC context.
 * \param[in] mac                       Buffer containing the MAC 2/3.
 * \param[in] mac_len                   Size of the \p mac buffer in bytes.
 * \param[out] signature                Buffer where the generated
 *                                      Signature_or_MAC 2/3 is to be written.
 * \param signature_size                Size of the \p signature buffer in bytes.
 * \param[out] signature_length         On success, the number of bytes that make
 *                                      up the Signature_or_MAC 2/3.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_sign_or_mac_compute(const struct edhoc_context *edhoc_context,
			      const void *private_key_id,
			      const struct mac_context *mac_context,
			      const uint8_t *mac, size_t mac_len,
			      uint8_t *signature, size_t signature_size,
			      size_t *signature_length);

/**
 * \brief Verify Signature_or_MAC 2/3 buffer.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] mac_context               MAC context.
 * \param[in] public_key                Buffer containing authentication public key.
 * \param public_key_length             Size of the \p public_key buffer in bytes.
 * \param[in] signature                 Buffer containing Signature_or_MAC 2/3.
 * \param signature_length              Size of the \p signature buffer in bytes.
 * \param[in] mac                       Buffer containing MAC 2/3.
 * \param mac_length                    Size of the \p mac buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_sign_or_mac_verify(const struct edhoc_context *edhoc_context,
			     const struct mac_context *mac_context,
			     const uint8_t *public_key,
			     size_t public_key_length, const uint8_t *signature,
			     size_t signature_length, const uint8_t *mac,
			     size_t mac_length);

/**@}*/

#endif /* EDHOC_MAC_INTERNAL_H */
