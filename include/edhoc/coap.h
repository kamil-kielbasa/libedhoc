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
 * (RFC 9528: A.2). The sender fills a \ref edhoc_coap_prepended_fields and
 * prepends what it needs; the receiver fills a
 * \ref edhoc_coap_extracted_fields and strips the prepended data before EDHOC
 * processing. Each call picks up where the previous one left off, so calls in
 * either direction compose.
 * @{
 */

/**
 * \brief Working buffer for building a CoAP payload to send.
 *
 * Initialise \p buffer and \p capacity to the whole output buffer and leave
 * \p length at zero. Every prepend call writes at \p buffer + \p length and
 * advances \p length, so what it prepends lands after the data prepended
 * before it and still before the EDHOC message. Compose the EDHOC message into
 * the remaining space and add its length to \p length; the payload to send is
 * then the first \p length bytes of \p buffer.
 */
struct edhoc_coap_prepended_fields {
	/** Output buffer. */
	uint8_t *buffer;
	/** Capacity of \p buffer in bytes. */
	size_t capacity;
	/** Bytes written so far. */
	size_t length;
};

/**
 * \brief Working buffer for parsing a received CoAP payload.
 *
 * Initialise \p buffer and \p length to the received payload and leave
 * \p consumed at zero. Every extract call reads at \p buffer + \p consumed and
 * advances \p consumed. The bare EDHOC message is then \p buffer +
 * \p consumed, of \p length - \p consumed bytes.
 */
struct edhoc_coap_extracted_fields {
	/** Received payload. */
	const uint8_t *buffer;
	/** Size of the received payload in bytes. */
	size_t length;
	/** Bytes read so far. */
	size_t consumed;

	/** Forward flow: the CBOR \c true indicator was found (set by
	 *  \ref edhoc_coap_extract_flow_info). */
	bool is_forward_flow;
	/** Reverse flow: the payload was empty (set by
	 *  \ref edhoc_coap_extract_flow_info). */
	bool is_reverse_flow;
	/** Connection identifier extracted by
	 *  \ref edhoc_coap_extract_connection_id. A view into \p buffer. */
	struct edhoc_buffer connection_id;
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
bool edhoc_coap_connection_id_equal(const struct edhoc_buffer *conn_id_1,
				    const struct edhoc_buffer *conn_id_2);

/**@}*/

/** \addtogroup edhoc-api-buffer-utils
 * @{
 */

/**
 * \note Initialise the prepend buffer with designated initialisers before use:
 * \code
 * struct edhoc_coap_prepended_fields prepended_fields = {
 *     .buffer = buffer,
 *     .capacity = ARRAY_SIZE(buffer),
 * };
 * \endcode
 * Then prepend as needed, compose the EDHOC message into
 * \c buffer + \c length with \c capacity - \c length bytes available, and add
 * its length to \c length.
 */

/**
 * \brief Prepend the forward-flow indicator before the EDHOC message.
 *
 * Writes the CBOR simple value \c true (0xf5) that marks message 1 of the
 * forward flow / a new EDHOC session (RFC 9528: A.2).
 *
 * \param[in,out] prepended_fields     Prepend buffer.
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
 * CBOR-encodes \p conn_id and writes it before the EDHOC message, as the CoAP
 * client must do on the messages it sends (RFC 9528: A.2): the peer's C_R in
 * the forward flow, or C_I in the reverse flow.
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
	const struct edhoc_buffer *conn_id);

/**
 * \note Initialise the extract buffer with designated initialisers before use:
 * \code
 * struct edhoc_coap_extracted_fields extracted_fields = {
 *     .buffer = payload,
 *     .length = payload_length,
 * };
 * \endcode
 */

/**
 * \brief Detect and strip the flow indicator at the start of the payload.
 *
 * Inspects the first unconsumed byte (RFC 9528: A.2):
 * - an empty payload indicates the reverse flow (\p is_reverse_flow);
 * - a leading CBOR \c true (0xf5) indicates the forward flow
 *   (\p is_forward_flow), which is then consumed;
 * - otherwise no indicator is present and nothing is consumed.
 *
 * \param[in,out] extracted_fields     Extract buffer; the flow flags are set
 *                                     and the indicator consumed.
 *
 * \retval #EDHOC_SUCCESS
 *         Success (indicator stripped, or none present / empty payload).
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_coap_extract_flow_info(
	struct edhoc_coap_extracted_fields *extracted_fields);

/**
 * \brief Extract and strip the prepended connection identifier.
 *
 * CBOR-decodes the connection identifier at the first unconsumed byte into
 * \p connection_id and consumes it, leaving the bare EDHOC message
 * (RFC 9528: A.2).
 *
 * \param[in,out] extracted_fields     Extract buffer; \p connection_id is set
 *                                     and the identifier consumed on success.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_coap_extract_connection_id(
	struct edhoc_coap_extracted_fields *extracted_fields);

/**@}*/

#endif /* EDHOC_COAP_H */
