/**
 * \file    edhoc_psk_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC-PSK message flow (draft-ietf-lake-edhoc-psk: 5).
 *
 *          Method 4 leaves messages 1 and 4 to the classic flow and replaces
 *          only messages 2 and 3, which carry no credential and no
 *          Signature_or_MAC.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_PSK_INTERNAL_H
#define EDHOC_PSK_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** EDHOC context, defined by \c edhoc_context_internal.h. */
struct edhoc_context;

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-psk EDHOC-PSK message flow
 * @{
 */

/**
 * \brief Is the session running the pre-shared key method?
 *
 * \param[in] edhoc_context             EDHOC context.
 *
 * \return \c true when the negotiated method is \ref EDHOC_METHOD_4.
 */
bool edhoc_psk_is_selected(const struct edhoc_context *edhoc_context);

/**
 * \brief Compose EDHOC-PSK message 2 (draft-ietf-lake-edhoc-psk: 5.2.2).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_2                Buffer for the message.
 * \param message_2_size                Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length         On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_psk_message_2_compose(struct edhoc_context *edhoc_context,
				uint8_t *message_2, size_t message_2_size,
				size_t *message_2_length);

/**
 * \brief Process EDHOC-PSK message 2 (draft-ietf-lake-edhoc-psk: 5.2.3).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_2                 Received message.
 * \param message_2_length              Size of the \p message_2 buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_psk_message_2_process(struct edhoc_context *edhoc_context,
				const uint8_t *message_2,
				size_t message_2_length);

/**
 * \brief Compose EDHOC-PSK message 3 (draft-ietf-lake-edhoc-psk: 5.3.2).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_3                Buffer for the message.
 * \param message_3_size                Size of the \p message_3 buffer in bytes.
 * \param[out] message_3_length         On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_psk_message_3_compose(struct edhoc_context *edhoc_context,
				uint8_t *message_3, size_t message_3_size,
				size_t *message_3_length);

/**
 * \brief Process EDHOC-PSK message 3 (draft-ietf-lake-edhoc-psk: 5.3.3).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_3                 Received message.
 * \param message_3_length              Size of the \p message_3 buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_psk_message_3_process(struct edhoc_context *edhoc_context,
				const uint8_t *message_3,
				size_t message_3_length);

/**@}*/

#endif /* EDHOC_PSK_INTERNAL_H */
