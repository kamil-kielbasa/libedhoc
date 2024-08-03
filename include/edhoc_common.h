/**
 * \file    edhoc_common.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC common implementations:
 *          - CBOR utilities.
 *          - MAC context.
 *          - MAC & Signature_or_MAC.
 * \version 0.4
 * \date    2024-07-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_COMMON_H
#define EDHOC_COMMON_H

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include "edhoc_context.h"
#include "edhoc_ead.h"
#include "edhoc_credentials.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-common-structures EDHOC common structures
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

	/** Is compact encoding possible? */
	bool id_cred_is_comp_enc;
	/** Credentials identifer encoding type. */
	enum edhoc_encode_type id_cred_enc_type;
	/** Buffer containing credentials identifer integer representation. */
	int32_t id_cred_int;
	/** Buffer containing credentials identifer byte string representation. */
	uint8_t id_cred_bstr[CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID + 1];
	/** Size of the \p id_cred_bstr buffer in bytes. */
	size_t id_cred_bstr_len;

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

/**
 * \brief RFC 9528:
 *        - 5.3.2. Responder Composition of Message 2.
 *          - PLAINTEXT_2.
 *        - 5.4.2. Initiator Composition of Message 3.
 *          - PLAINTEXT_3.
 */
struct plaintext {
	/** Authentication credentials. */
	struct edhoc_auth_creds auth_cred;

	/** Buffer containing cborised Signature_or_MAC (2/3). */
	const uint8_t *sign_or_mac;
	/** Size of the \p sign_or_mac buffer in bytes. */
	size_t sign_or_mac_len;

	/** Buffer containing cborised EAD (2/3). */
	const uint8_t *ead;
	/** Size of the \p ead buffer in bytes. */
	size_t ead_len;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-common-cbor EDHOC common CBOR
 * @{
 */

/** 
 * \brief CBOR integer memory requirements.
 *
 * \param value                         Raw integer value.
 *
 * \return Number of bytes.
 */
size_t edhoc_cbor_int_mem_req(int32_t value);

/** 
 * \brief CBOR text stream overhead.
 *
 * \param length                        Length of buffer to CBOR as tstr.
 *
 * \return Number of overhead bytes.
 */
size_t edhoc_cbor_tstr_oh(size_t length);

/** 
 * \brief CBOR byte stream overhead.
 *
 * \param length                        Length of buffer to CBOR as bstr.
 *
 * \return Number of overhead bytes.
 */
size_t edhoc_cbor_bstr_oh(size_t length);

/** 
 * \brief CBOR map overhead.
 *
 * \param items                         Number of items for map.
 *
 * \return Number of overhead bytes.
 */
size_t edhoc_cbor_map_oh(size_t items);

/** 
 * \brief CBOR array overhead.
 *
 * \param items                         Number of items for array.
 *
 * \return Number of overhead bytes.
 */
size_t edhoc_cbor_array_oh(size_t items);

/**@}*/

/** \defgroup edhoc-common-mac-context EDHOC common MAC context
 * @{
 */

/**
 * \brief Compute required buffer length for MAC 2/3 context.
 * 
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] credentials               Authentication credentials.
 * \param[out] mac_context_length       On success, number of bytes that make up MAC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_comp_mac_context_length(const struct edhoc_context *edhoc_context,
				  const struct edhoc_auth_creds *credentials,
				  size_t *mac_context_length);

/**
 * \brief Cborise items required by MAC 2/3 context.
 * 
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] credentials               Authentication credentials.
 * \param[out] mac_context              On success, generated MAC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_comp_mac_context(const struct edhoc_context *edhoc_context,
			   const struct edhoc_auth_creds *credentials,
			   struct mac_context *mac_context);

/**@}*/

/** \defgroup edhoc-common-sign-or-mac EDHOC common Signature_or_MAC
 * @{
 */

/**
 * \brief Compute required buffer length for MAC 2/3.
 * 
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] mac_length               On success, number of bytes that make up
 *                                      MAC 2/3 length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_comp_mac_length(const struct edhoc_context *edhoc_context,
			  size_t *mac_length);

/**
 * \brief Compute MAC 2/3 buffer.
 * 
 * \param[in] edhoc_context             EDHOC context.                 
 * \param[in] mac_context               MAC context.
 * \param[out] mac                      Buffer where the generated MAC 2/3 is to be written.
 * \param mac_length                    Size of the \p mac buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_comp_mac(const struct edhoc_context *edhoc_context,
		   const struct mac_context *mac_context, uint8_t *mac,
		   size_t mac_length);

/**
 * \brief Compute required buffer length for Signature_or_MAC 2/3.
 * 
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] sign_or_mac_length       On success, number of bytes that make up
 *                                      Signature_or_MAC 2/3 length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_comp_sign_or_mac_length(const struct edhoc_context *edhoc_context,
				  size_t *sign_or_mac_length);

/**
 * \brief Compute Signature_or_MAC 2/3 buffer.
 * 
 * \param[in] edhoc_context             EDHOC context.
 * \param[in] cred                      Authentication credentials.
 * \param[in] mac_context               MAC context.
 * \param[in] mac                       Buffer containing the MAC 2/3.
 * \param[in] mac_len                   Size of the \p mac buffer in bytes.
 * \param[out] signature                Buffer where the generated 
 *                                      Signature_or_MAC 2/3 is to be written.
 * \param signature_size                Size of the \p signature buffer in bytes.
 * \param[out] signature_length         On success, the number of bytes that make
 *                                      up the Signature_or_MAC 2/3.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_comp_sign_or_mac(const struct edhoc_context *edhoc_context,
			   const struct edhoc_auth_creds *cred,
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_verify_sign_or_mac(const struct edhoc_context *edhoc_context,
			     const struct mac_context *mac_context,
			     const uint8_t *public_key,
			     size_t public_key_length, const uint8_t *signature,
			     size_t signature_length, const uint8_t *mac,
			     size_t mac_length);

/**@}*/

#endif /* EDHOC_COMMON_H */
