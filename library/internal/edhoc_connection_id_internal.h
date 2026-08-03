/**
 * \file    edhoc_connection_id_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC connection identifier (RFC 9528: 3.3).
 *
 *          C_I and C_R are byte strings. The one byte CBOR integer form of
 *          RFC 9528: 3.3.2 is a transport encoding that this module applies and
 *          undoes, so the rest of the library only ever sees bytes.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CONNECTION_ID_INTERNAL_H
#define EDHOC_CONNECTION_ID_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/**
 * \brief Connection identifier owned by the context.
 */
struct connection_id {
	/** Identifier bytes. */
	uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID];
	/** Number of valid bytes in \p value. */
	size_t length;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Check whether \p cid travels as a CBOR integer (RFC 9528: 3.3.2).
 *
 * \param[in] connection_id             Connection identifier.
 * \param[out] value                    On success, the integer to encode.
 *
 * \return True if the compact form applies, otherwise false.
 */
bool edhoc_connection_id_compact(const struct connection_id *connection_id,
				 int32_t *value);

/**
 * \brief Number of bytes the encoded connection identifier occupies.
 *
 * \param[in] connection_id             Connection identifier.
 *
 * \return Number of bytes, or zero on failure.
 */
size_t
edhoc_connection_id_encoded_length(const struct connection_id *connection_id);

/**
 * \brief Encode a connection identifier, applying RFC 9528: 3.3.2.
 *
 * \param[in] connection_id             Connection identifier.
 * \param[out] buffer                   On success, the encoded identifier.
 * \param buffer_length                 Size of \p buffer in bytes.
 * \param[out] length                   On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_connection_id_encode(const struct connection_id *connection_id,
			       uint8_t *buffer, size_t buffer_length,
			       size_t *length);

/**
 * \brief Recover a connection identifier from the compact integer form.
 *
 * \param value                         Decoded CBOR integer.
 * \param[out] connection_id            On success, the identifier.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_connection_id_from_int(int32_t value,
				 struct connection_id *connection_id);

/**
 * \brief Recover a connection identifier from the byte string form.
 *
 * \param[in] value                     Decoded byte string.
 * \param length                        Size of \p value in bytes.
 * \param[out] connection_id            On success, the identifier.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_connection_id_from_bstr(const uint8_t *value, size_t length,
				  struct connection_id *connection_id);

#endif /* EDHOC_CONNECTION_ID_INTERNAL_H */
