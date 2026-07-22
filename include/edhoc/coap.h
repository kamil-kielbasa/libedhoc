/**
 * \file    coap.h
 * \author  Assa Abloy
 * \brief   Helpers for transferring EDHOC messages over CoAP (RFC 9528: A.2).
 *
 *          When EDHOC runs over CoAP the party acting as CoAP client prepends,
 *          to each message it sends, either the flow indicator (the CBOR simple
 *          value \c true, before message 1 of the forward flow) or the
 *          connection identifier selected by the peer. These helpers build such
 *          a prepended buffer on the sending side and strip it on the receiving
 *          side, and compare connection identifiers.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_COAP_H
#define EDHOC_COAP_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* EDHOC headers: */
#include <edhoc/types.h>
#include <edhoc/values.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-api-buffer-utils EDHOC CoAP buffer utilities
 *
 * Build and parse a CoAP payload that carries an EDHOC message optionally
 * prepended with a flow indicator and/or a connection identifier
 * (RFC 9528: A.2). The sender fills a \ref edhoc_coap_prepended_fields, prepends
 * what it needs, composes the EDHOC message into the reserved area, then
 * recomputes the total size. The receiver fills a
 * \ref edhoc_coap_extracted_fields and strips the prepended data before EDHOC
 * processing.
 * @{
 */

/**
 * \brief Working buffer for building a CoAP payload to send.
 *
 * Initialise \p buffer / \p buffer_size to the whole output buffer and point
 * \p edhoc_message_ptr / \p edhoc_message_size at the same buffer. Each prepend
 * call advances \p edhoc_message_ptr past the bytes it wrote and shrinks
 * \p edhoc_message_size; compose the EDHOC message there, then call
 * \ref edhoc_coap_prepend_recalculate_size.
 */
struct edhoc_coap_prepended_fields {
	/** Output buffer holding the prepended data followed by the EDHOC message. */
	uint8_t *buffer;
	/** In: capacity of \p buffer; out: total used size after recalculation. */
	size_t buffer_size;
	/** Where the EDHOC message is to be written (advanced past prepended data). */
	uint8_t *edhoc_message_ptr;
	/** In: space left for the EDHOC message; out (after compose): its length. */
	size_t edhoc_message_size;
};

/**
 * \brief Working buffer for parsing a received CoAP payload.
 *
 * Initialise \p buffer / \p buffer_size to the received payload and point
 * \p edhoc_message_ptr / \p edhoc_message_size at the same buffer. Each extract
 * call advances \p edhoc_message_ptr past the bytes it consumed and shrinks
 * \p edhoc_message_size, leaving the bare EDHOC message to process.
 */
struct edhoc_coap_extracted_fields {
	/** Received payload. */
	const uint8_t *buffer;
	/** Size of the received payload in bytes. */
	size_t buffer_size;
	/** Start of the EDHOC message (advanced past extracted data). */
	const uint8_t *edhoc_message_ptr;
	/** Remaining EDHOC message length in bytes. */
	size_t edhoc_message_size;

	/** Forward flow: the CBOR \c true indicator was found (set by
	 *  \ref edhoc_coap_extract_flow_info). */
	bool is_forward_flow;
	/** Reverse flow: the payload was empty (set by
	 *  \ref edhoc_coap_extract_flow_info). */
	bool is_reverse_flow;
	/** Connection identifier extracted by
	 *  \ref edhoc_coap_extract_connection_id. */
	struct edhoc_connection_id extracted_conn_id;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-api-connection-id EDHOC CoAP connection-id utilities
 *
 * Compare EDHOC connection identifiers, e.g. to match the identifier extracted
 * from an incoming CoAP message against the one selected for a session.
 * @{
 */

/**
 * \brief Compare two connection identifiers for equality.
 *
 * \param[in] conn_id_1                First connection identifier.
 * \param[in] conn_id_2                Second connection identifier.
 *
 * \return \c true if both encode the same connection identifier, else \c false.
 */
bool edhoc_coap_connection_id_equal(const struct edhoc_connection_id *conn_id_1,
				    const struct edhoc_connection_id *conn_id_2);

/**@}*/

/** \addtogroup edhoc-api-buffer-utils
 * @{
 */

/**
 * \note Initialise the prepend buffer with designated initialisers before use:
 * \code
 * struct edhoc_coap_prepended_fields prepended_fields = {
 *     .buffer = buffer,
 *     .buffer_size = buffer_size,
 *     .edhoc_message_ptr = buffer,
 *     .edhoc_message_size = buffer_size
 * };
 * \endcode
 * Then prepend as needed, compose the EDHOC message into
 * \c edhoc_message_ptr, and call \ref edhoc_coap_prepend_recalculate_size.
 */

/**
 * \brief Prepend the forward-flow indicator before the EDHOC message.
 *
 * Writes the CBOR simple value \c true (0xf5) that marks message 1 of the
 * forward flow / a new EDHOC session (RFC 9528: A.2), and reserves the rest of
 * the buffer for the EDHOC message.
 *
 * \param[in,out] prepended_fields     Prepend buffer (\p buffer and \p buffer_size set).
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_coap_prepend_flow(
	struct edhoc_coap_prepended_fields *prepended_fields);

/**
 * \brief Prepend a connection identifier before the EDHOC message.
 *
 * CBOR-encodes \p conn_id and prepends it, as the CoAP client must do on the
 * messages it sends (RFC 9528: A.2): the peer's C_R in the forward flow, or
 * C_I in the reverse flow.
 *
 * \param[in,out] prepended_fields     Prepend buffer.
 * \param[in] conn_id                  Connection identifier to prepend.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_coap_prepend_connection_id(
	struct edhoc_coap_prepended_fields *prepended_fields,
	const struct edhoc_connection_id *conn_id);

/**
 * \brief Finalise the payload size after composing the EDHOC message.
 *
 * Call once the EDHOC message has been composed into \p edhoc_message_ptr and
 * \p edhoc_message_size holds its actual length. Sets \p buffer_size to the
 * total bytes to send (prepended data + EDHOC message).
 *
 * \param[in,out] prepended_fields     Prepend buffer; \p buffer_size is updated
 *                                     to the total used size on success.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_coap_prepend_recalculate_size(
	struct edhoc_coap_prepended_fields *prepended_fields);

/**
 * \note Initialise the extract buffer with designated initialisers before use:
 * \code
 * struct edhoc_coap_extracted_fields extracted_fields = {
 *     .buffer = buffer,
 *     .buffer_size = buffer_size,
 *     .edhoc_message_ptr = buffer,
 *     .edhoc_message_size = buffer_size
 * };
 * \endcode
 */

/**
 * \brief Detect and strip the flow indicator at the start of the payload.
 *
 * Inspects the first byte (RFC 9528: A.2):
 * - an empty payload indicates the reverse flow (\p is_reverse_flow);
 * - a leading CBOR \c true (0xf5) indicates the forward flow
 *   (\p is_forward_flow), which is then consumed;
 * - otherwise no indicator is present and the buffer is left unchanged.
 *
 * \param[in,out] extracted_fields     Extract buffer; advanced past the
 *                                     indicator and flow flags set.
 *
 * \retval #EDHOC_SUCCESS
 *         Success (indicator stripped, or none present / empty buffer).
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_coap_extract_flow_info(
	struct edhoc_coap_extracted_fields *extracted_fields);

/**
 * \brief Extract and strip the prepended connection identifier.
 *
 * CBOR-decodes the connection identifier at the start of the payload into
 * \p extracted_conn_id and advances past it, leaving the bare EDHOC message
 * (RFC 9528: A.2).
 *
 * \param[in,out] extracted_fields     Extract buffer; \p extracted_conn_id is
 *                                     set and the buffer advanced on success.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_coap_extract_connection_id(
	struct edhoc_coap_extracted_fields *extracted_fields);

/**@}*/

#endif /* EDHOC_COAP_H */
