/**
 * \file    edhoc.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC API.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
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
#define EDHOC_API_VERSION_MINOR 0

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
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_context_init(struct edhoc_context *edhoc_context);

/** 
 * \brief Deinitialize EDHOC context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_context_deinit(struct edhoc_context *edhoc_context);

/** 
 * \brief Set EDHOC method.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param method                        EDHOC method.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_set_method(struct edhoc_context *edhoc_context,
		     enum edhoc_method method);

/** 
 * \brief Set EDHOC supproted cipher suites.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] cipher_suite              EDHOC cipher suites.
 * \param cipher_suite_length           Number of the \p cipher_suite.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_set_connection_id(struct edhoc_context *edhoc_context,
			    struct edhoc_connection_id connection_id);

/** 
 * \brief Set user context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] user_context              User context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_set_user_context(struct edhoc_context *edhoc_context,
			   void *user_context);

/** 
 * \brief Bind EDHOC external authorization data (EAD) callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param ead                           EDHOC EAD structure with callbacks.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_ead(struct edhoc_context *edhoc_context, struct edhoc_ead ead);

/** 
 * \brief Bind EDHOC cryptographic keys callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param keys                          EDHOC cryptographic keys structure with callbacks.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_keys(struct edhoc_context *edhoc_context,
		    struct edhoc_keys keys);

/** 
 * \brief Bind EDHOC cryptographic operations callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param crypto                        EDHOC cryptographic operations structure with callbacks.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_crypto(struct edhoc_context *edhoc_context,
		      struct edhoc_crypto crypto);

/** 
 * \brief Bind EDHOC authentication credentials callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param credentials                   EDHOC authentication credentials structure with callbacks.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_credentials(struct edhoc_context *edhoc_context,
			   struct edhoc_credentials credentials);

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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure. 
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
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
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_export_oscore_session(struct edhoc_context *edhoc_context,
				uint8_t *master_secret,
				size_t master_secret_length,
				uint8_t *master_salt, size_t master_salt_length,
				uint8_t *sender_id, size_t sender_id_size,
				size_t *sender_id_length, uint8_t *recipient_id,
				size_t recipient_id_size,
				size_t *recipient_id_length);

/**@}*/

#endif /* EDHOC_H */
