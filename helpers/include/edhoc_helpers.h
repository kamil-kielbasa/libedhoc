/**
 * \file    edhoc_helpers.h
 * \author  Assa Abloy
 * \brief   EDHOC Utilities API:
 *          - Connection ID utilities.
 *          - Buffer utilities (prepend/extract).
 * \version 1.0
 * \date    2026-01-27
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_HELPERS_H
#define EDHOC_HELPERS_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* EDHOC headers: */
#include "edhoc_context.h"
#include "edhoc_values.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-api-buffer-utils EDHOC Buffer Utilities API
 * @{
 */

/**
 * \brief Helper structure for prepending data before EDHOC messages.
 */
struct edhoc_prepended_fields {
    /** Complete buffer including prepended data and EDHOC message. */
    uint8_t *buffer;
    /** Total size of the buffer. */
    size_t buffer_size;
    /** Pointer to where EDHOC message should be written (after prepended data). */
    uint8_t *edhoc_message_ptr;
    /** Available size for EDHOC message (after composition, contains actual message length). */
    size_t edhoc_message_size;
};

/**
 * \brief Helper structure for extracting data from received messages.
 */
struct edhoc_extracted_fields {
    /** Complete received buffer. */
    const uint8_t *buffer;
    /** Size of received buffer. */
    size_t buffer_size;
    /** Pointer to EDHOC message (after extracted data). */
    const uint8_t *edhoc_message_ptr;
    /** Size of EDHOC message. */
    size_t edhoc_message_size;
    
    /** True if forward flow detected (CBOR true found, set by edhoc_extract_flow_info). */
    bool is_forward_flow;
    /** True if reverse flow detected (empty buffer, set by edhoc_extract_flow_info). */
    bool is_reverse_flow;
    /** Extracted connection identifier (set by edhoc_extract_connection_id). */
    struct edhoc_connection_id extracted_conn_id;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-api-connection-id EDHOC Connection ID Utilities API
 * @{
 */

/**
 * \brief Compare two connection identifiers for equality.
 * 
 * \param[in] conn_id_1                First connection identifier.
 * \param[in] conn_id_2                Second connection identifier.
 * 
 * \return true if connection IDs are equal, false otherwise.
 */
bool edhoc_connection_id_equal(
    const struct edhoc_connection_id *conn_id_1,
    const struct edhoc_connection_id *conn_id_2);

/**@}*/

/** \defgroup edhoc-api-buffer-utils EDHOC Buffer Utilities API
 * @{
 */

/**
 * \note Initialize prepend buffer directly using struct initialization:
 * \code
 * struct edhoc_prepended_fields prepended_fields = {
 *     .buffer = buffer,
 *     .buffer_size = buffer_size,
 *     .edhoc_message_ptr = buffer,
 *     .edhoc_message_size = buffer_size
 * };
 * \endcode
 * 
 * \note After calling edhoc_prepend_recalculate_size(), buffer_size contains
 *       the actual used size (prepended + EDHOC message).
 */

/**
 * \brief Prepend flow indicator (CBOR true) to buffer before EDHOC message.
 * 
 * Prepends EDHOC_CBOR_TRUE to indicate forward flow.
 * The prepend buffer must be initialized with buffer and buffer_size before calling this function.
 * 
 * \param[in,out] prepend_buf          Prepend buffer structure (must have buffer and buffer_size set).
 * 
 * \retval #EDHOC_SUCCESS Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT Invalid parameters.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL Not enough space.
 */
int edhoc_prepend_flow(
    struct edhoc_prepended_fields *prepended_fields);

/**
 * \brief Prepend connection identifier to buffer before EDHOC message.
 * 
 * Encodes and prepends the connection identifier.
 * 
 * \param[in,out] prepend_buf          Prepend buffer structure.
 * \param[in] conn_id                  Connection identifier to prepend.
 * 
 * \retval #EDHOC_SUCCESS Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT Invalid parameters.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL Not enough space.
 * \retval #EDHOC_ERROR_CBOR_FAILURE Encoding failure.
 */
int edhoc_prepend_connection_id(
    struct edhoc_prepended_fields *prepended_fields,
    const struct edhoc_connection_id *conn_id);

/**
 * \brief Recalculate total size after EDHOC message composition.
 * 
 * Recalculates total size after EDHOC message composition and updates
 * buffer_size to reflect the actual used size (prepended + EDHOC message).
 * The EDHOC message length is taken from edhoc_message_size after composition.
 * 
 * \param[in,out] prepended_fields          Prepend buffer structure.
 *                                          On success, buffer_size is updated to the actual used size.
 * 
 * \retval #EDHOC_SUCCESS Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT Invalid parameters.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL Total size exceeds buffer capacity.
 */
int edhoc_prepend_recalculate_size(
    struct edhoc_prepended_fields *prepended_fields);

/**
 * \note Initialize extract buffer directly using struct initialization:
 * \code
 * struct edhoc_extracted_fields extracted_fields = {
 *     .buffer = buffer,
 *     .buffer_size = buffer_size,
 *     .edhoc_message_ptr = buffer,
 *     .edhoc_message_size = buffer_size
 * };
 * \endcode
 */

/**
 * \brief Extract flow information from buffer.
 * 
 * Checks the beginning of the buffer for flow indicators:
 * - Empty buffer indicates reverse flow
 * - CBOR true (EDHOC_CBOR_TRUE) indicates forward flow
 * - Otherwise, no flow indicator present
 * 
 * If a flow indicator is found, it is extracted and the extract buffer
 * is updated to point to the EDHOC message after the indicator.
 * Flow information is stored in extract_buf->is_forward_flow and extract_buf->is_reverse_flow.
 * 
 * \param[in,out] extract_buf          Extract buffer structure.
 * 
 * \retval #EDHOC_SUCCESS Success (flow info extracted or buffer is empty).
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT Invalid parameters.
 */
int edhoc_extract_flow_info(
    struct edhoc_extracted_fields *extracted_fields);

/**
 * \brief Extract connection identifier from buffer.
 * 
 * Extracts and decodes a connection identifier from the beginning of the buffer.
 * The connection identifier is stored in extract_buf->extracted_conn_id and
 * The connection identifier is stored in extract_buf->extracted_conn_id on success.
 * The extract buffer is updated to point to the EDHOC message after the connection ID.
 * 
 * \param[in,out] extract_buf          Extract buffer structure.
 * 
 * \retval #EDHOC_SUCCESS Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT Invalid parameters.
 * \retval #EDHOC_ERROR_CBOR_FAILURE Decoding failure.
 */
int edhoc_extract_connection_id(
    struct edhoc_extracted_fields *extracted_fields);

/**@}*/

#endif /* EDHOC_HELPERS_H */

