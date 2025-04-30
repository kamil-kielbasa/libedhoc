/**
 * \file    edhoc.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC API.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_H
#define EDHOC_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* EDHOC headers: */
#include "edhoc_context.h"
#include "edhoc_credentials.h"
#include "edhoc_crypto.h"
#include "edhoc_ead.h"
#include "edhoc_macros.h"
#include "edhoc_values.h"

/* Defines ----------------------------------------------------------------- */

/** \defgroup edhoc-api-version EDHOC API version
 * @{
 */

/** The major version of this implementation of the EDHOC API. */
#define EDHOC_API_VERSION_MAJOR 1

/** The minor version of this implementation of the EDHOC API. */
#define EDHOC_API_VERSION_MINOR 4

/**@}*/

/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-api-setters EDHOC API setters
 * @{
 */

/** 
 * \brief Initialize EDHOC context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Input parameter is recognized as invalid.
 */
int edhoc_context_init(struct edhoc_context *edhoc_context);

/** 
 * \brief Deinitialize EDHOC context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Input parameter is recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_context_deinit(struct edhoc_context *edhoc_context);

/** 
 * \brief Set EDHOC mode (classical or pre-shared key).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param mode				EDHOC mode.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Input parameter is recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_mode(struct edhoc_context *edhoc_context, enum edhoc_mode mode);

/** 
 * \brief Set EDHOC methods.
 *
 * According to RFC 9528: 3.2. Method.  It is required to set at least one method 
 * but no more than \p EDHOC_METHOD_MAX.
 * 
 * Depends on processing side:
 * - Initiator will always read first value (method[0]) in message 1 compose.
 * - Responder will iterator over all method and try to match in message 1 process.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] method                    EDHOC method.
 * \param method_length			Number of the \p method.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_methods(struct edhoc_context *edhoc_context,
		      const enum edhoc_method *method, size_t method_length);

/** 
 * \brief Set EDHOC cipher suites.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] cipher_suite              EDHOC cipher suites.
 * \param cipher_suite_length           Number of the \p cipher_suite.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_cipher_suites(struct edhoc_context *edhoc_context,
			    const struct edhoc_cipher_suite *cipher_suite,
			    size_t cipher_suite_length);

/** 
 * \brief Set EDHOC connection identifier.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] connection_id             EDHOC connection identifier.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_connection_id(struct edhoc_context *edhoc_context,
			    const struct edhoc_connection_id *connection_id);

/** 
 * \brief Set user context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] user_context              User context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_user_context(struct edhoc_context *edhoc_context,
			   void *user_context);

/** 
 * \brief Bind EDHOC external authorization data (EAD) callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] ead                       EDHOC EAD structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_ead(struct edhoc_context *edhoc_context,
		   const struct edhoc_ead *ead);

/** 
 * \brief Bind EDHOC cryptographic keys callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] keys                      EDHOC cryptographic keys structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_keys(struct edhoc_context *edhoc_context,
		    const struct edhoc_keys *keys);

/** 
 * \brief Bind EDHOC cryptographic operations callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] crypto                    EDHOC cryptographic operations structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_crypto(struct edhoc_context *edhoc_context,
		      const struct edhoc_crypto *crypto);

/** 
 * \brief Bind EDHOC authentication credentials callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] credentials               EDHOC authentication credentials structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_credentials(struct edhoc_context *edhoc_context,
			   const struct edhoc_credentials *credentials);

/**@}*/

/** \defgroup edhoc-api-messages EDHOC messages API
 * @{
 */

/** 
 * \brief Compose EDHOC message 1.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_1                Buffer where the generated message 1 is to be written.
 * \param message_1_size                Size of the \p message_1 buffer in bytes.
 * \param[out] message_1_length         On success, the number of bytes that make up the message 1.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Ephemeral Diffie-Hellman key pair or agreement failure.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         External authorization data compose failure.
 */
int edhoc_message_1_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_1, size_t message_1_size,
			    size_t *message_1_length);

/**
 * \brief Process EDHOC message 1.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_1                 Buffer containing the message 1.
 * \param message_1_length              Size of the \p message_1 buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 * \retval #EDHOC_ERROR_MSG_1_PROCESS_FAILURE
 *         Error on EDHOC layer during processing. 
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         External authorization data process failure.
 */
int edhoc_message_1_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_1, size_t message_1_length);

/**
 * \brief Compose EDHOC message 2.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_2                Buffer where the generated message 2 is to be written.
 * \param message_2_size                Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length         On success, the number of bytes that make up the message 2.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Computation of transcript hash failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Ephemeral Diffie-Hellman key pair or agreement failure.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials fetch/verify failure.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         External authorization data compose failure.
 */
int edhoc_message_2_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_2, size_t message_2_size,
			    size_t *message_2_length);

/**
 * \brief Process EDHOC message 2.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_2                 Buffer containing the message 2.
 * \param message_2_length              Size of the \p message_2 buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_MSG_2_PROCESS_FAILURE
 *         Error on EDHOC layer during processing. 
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Computation of transcript hash failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Ephemeral Diffie-Hellman key pair or agreement failure.
 * \retval #EDHOC_ERROR_INVALID_MAC_2
 *         Invalid MAC_2.
 * \retval #EDHOC_ERROR_INVALID_SIGN_OR_MAC_2
 *         Invalid Signature_or_MAC_2.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials fetch/verify failure.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         External authorization data process failure.
 */
int edhoc_message_2_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_2, size_t message_2_length);

/**
 * \brief Compose EDHOC message 3.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_3                Buffer where the generated message 3 is to be written.
 * \param message_3_size                Size of the \p message_3 buffer in bytes.
 * \param[out] message_3_length         On success, the number of bytes that make up the message 3.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Computation of transcript hash failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials fetch/verify failure.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         External authorization data compose failure.
 */
int edhoc_message_3_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_3, size_t message_3_size,
			    size_t *message_3_length);

/**
 * \brief Process EDHOC message 3.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_3                 Buffer containing the message 3.
 * \param message_3_length              Size of the \p message_3 buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 * \retval #EDHOC_ERROR_MSG_3_PROCESS_FAILURE
 *         Error on EDHOC layer during processing. 
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Computation of transcript hash failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 * \retval #EDHOC_ERROR_INVALID_MAC_3
 *         Invalid EDHOC MAC_3.
 * \retval #EDHOC_ERROR_INVALID_SIGN_OR_MAC_3
 *         Invalid EDHOC Signature_or_MAC_3.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials fetch/verify failure.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         External authorization data process failure.
 */
int edhoc_message_3_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_3, size_t message_3_length);

/**
 * \brief Compose EDHOC message 4.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_4                Buffer where the generated message 4 is to be written.
 * \param message_4_size                Size of the \p message_4 buffer in bytes.
 * \param[out] message_4_length         On success, the number of bytes that make up the message 4.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         External authorization data compose failure.
 */
int edhoc_message_4_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_4, size_t message_4_size,
			    size_t *message_4_length);

/**
 * \brief Process EDHOC message 4.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_4                 Buffer containing the message 4.
 * \param message_4_length              Size of the \p message_4 buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_MSG4_PROCESS_FAILURE
 *         Error on EDHOC layer during processing. 
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_MSG_4_PROCESS_FAILURE
 *         External authorization data process failure.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         External authorization data process failure.
 */
int edhoc_message_4_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_4, size_t message_4_length);

/**
 * \brief Compose EDHOC message error.
 *
 * \param[out] message_error            Buffer where the generated message error is to be written.
 * \param message_error_size            Size of the \p message_error buffer in bytes.
 * \param[out] message_error_length     On success, the number of bytes that make up the message error.
 * \param error_code                    EDHOC error code.
 * \param[in] error_info                EDHOC error information.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 */
int edhoc_message_error_compose(uint8_t *message_error,
				size_t message_error_size,
				size_t *message_error_length,
				enum edhoc_error_code error_code,
				const struct edhoc_error_info *error_info);

/**
 * \brief Process EDHOC message error.
 *
 * \param[in] message_error             Buffer containing the message error.
 * \param message_error_length          Size of the \p message_error buffer in bytes.
 * \param[out] error_code               EDHOC error code.
 * \param[out] error_info               EDHOC error information.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 */
int edhoc_message_error_process(const uint8_t *message_error,
				size_t message_error_length,
				enum edhoc_error_code *error_code,
				struct edhoc_error_info *error_info);

/**@}*/

/** \defgroup edhoc-api-exporters EDHOC exporters API
 * @{
 */

/**
 * \brief Psuedorandom key exporter for derivation keying material.
 * 
 * \param[in,out] edhoc_context         EDHOC context.
 * \param label                         PRK exporter label.
 * \param[out] secret                   Buffer where the generated secret is to be written.
 * \param secret_length                 Size of the \p secret buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 */
int edhoc_export_prk_exporter(struct edhoc_context *edhoc_context, size_t label,
			      uint8_t *secret, size_t secret_length);

/**
 * \brief Export key update for the new OSCORE security session.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] entropy                   Buffer containing the entropy for key update.
 * \param entropy_length                Size of the \p entropy buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 */
int edhoc_export_key_update(struct edhoc_context *edhoc_context,
			    const uint8_t *entropy, size_t entropy_length);

/**
 * \brief Export the OSCORE security session.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] master_secret            Buffer where the exported master secret is to be written.
 * \param master_secret_length          Size of the \p master_secret buffer in bytes.
 * \param[out] master_salt              Buffer where the exported master salt is to be written.
 * \param master_salt_length            Size of the \p master_salt buffer in bytes.
 * \param[out] sender_id                Buffer where the exported sender id is to be written.
 * \param sender_id_size                Size of the \p sender_id buffer in bytes.
 * \param[out] sender_id_length         On success, the number of bytes that make up the sender id.
 * \param[out] recipient_id             Buffer where the exported recipient id is to be written.
 * \param recipient_id_size             Size of the \p recipient_id buffer in bytes.
 * \param[out] recipient_id_length      On success, the number of bytes that make up the recipient id.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 */
int edhoc_export_oscore_session(struct edhoc_context *edhoc_context,
				uint8_t *master_secret,
				size_t master_secret_length,
				uint8_t *master_salt, size_t master_salt_length,
				uint8_t *sender_id, size_t sender_id_size,
				size_t *sender_id_length, uint8_t *recipient_id,
				size_t recipient_id_size,
				size_t *recipient_id_length);

/**
 * \brief Export the fresh pre-shared key (PSK).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] credential_psk           Buffer where the exported credential pre-shared key is to be written.
 * \param resumption_psk_length         Size of the \p credential_psk buffer in bytes.
 * \param[out] id_credential_psk        Buffer where the exported id credential pre-shared key is to be written.
 * \param id_credential_psk_length      Size of the \p id_credential_psk buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Processing code branch is not permitted by implementation.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographics operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Computation of pseudorandom key failure.
 */
int edhoc_export_psk(struct edhoc_context *edhoc_context,
		     uint8_t *credential_psk, size_t resumption_psk_length,
		     uint8_t *id_credential_psk,
		     size_t id_credential_psk_length);

/**@}*/

/** \defgroup edhoc-api-error EDHOC errors API
 * @{
 */

/**
 * \brief EDHOC error getter.
 * 
 * \param[in] edhoc_context             EDHOC context. 
 * \param[out] error_code               EDHOC error code.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_error_get_code(const struct edhoc_context *edhoc_context,
			 enum edhoc_error_code *error_code);

/**
 * \brief EDHOC own and peer cipher suites getter in case of \p EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE.
 * 
 * \param[in] edhoc_context             	EDHOC context. 
 * \param[out] cipher_suites			Buffer where the cipher suites values is to be written.
 * \param cipher_suites_size            	Size of the \p cipher_suites buffer in entries.
 * \param[out] cipher_suites_length     	On success, the number of entires that make up the cipher suites.
 * \param[out] peer_cipher_suites		Buffer where the peer cipher suites values is to be written.
 * \param peer_cipher_suites_size		Size of the \p peer_cipher_suites buffer in entries.
 * \param[out] peer_cipher_suites_length	On success, the number of entires that make up the peer cipher suites.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Combination of input parameters are recognized as invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Used buffer is too small.
 */
int edhoc_error_get_cipher_suites(const struct edhoc_context *edhoc_context,
				  int32_t *cipher_suites,
				  size_t cipher_suites_size,
				  size_t *cipher_suites_length,
				  int32_t *peer_cipher_suites,
				  size_t peer_cipher_suites_size,
				  size_t *peer_cipher_suites_length);

/**@}*/

#endif /* EDHOC_H */
