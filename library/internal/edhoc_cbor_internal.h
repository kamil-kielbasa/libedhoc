/**
 * \file    edhoc_cbor_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC CBOR utilities: head sizes and byte-string head encoding.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CBOR_INTERNAL_H
#define EDHOC_CBOR_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */

/** Longest head \ref edhoc_cbor_bstr_head_write emits: a one-byte initial byte
 *  plus a four-byte argument. A payload above \c UINT32_MAX needs a nine-byte
 *  head and is rejected. */
#define EDHOC_CBOR_BSTR_HEAD_MAX_LEN (5)

/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-cbor EDHOC CBOR utilities
 * @{
 */

/**
 * \brief Head length of a CBOR integer, which is its whole encoding.
 *
 * \param value                         Integer value to encode.
 *
 * \return Number of bytes: 1, 2, 3 or 5.
 */
size_t edhoc_cbor_int_head_length(int32_t value);

/**
 * \brief Head length of a CBOR text string, excluding the string itself.
 *
 * \param length                        Length of the text string in bytes.
 *
 * \return Number of bytes: 1, 2, 3, 5 or 9.
 */
size_t edhoc_cbor_tstr_head_length(size_t length);

/**
 * \brief Head length of a CBOR byte string, excluding the string itself.
 *
 * \param length                        Length of the byte string in bytes.
 *
 * \return Number of bytes: 1, 2, 3, 5 or 9.
 */
size_t edhoc_cbor_bstr_head_length(size_t length);

/**
 * \brief Head length of a CBOR map, excluding the pairs themselves.
 *
 * \param items                         Number of key-value pairs in the map.
 *
 * \return Number of bytes: 1, 2, 3, 5 or 9.
 */
size_t edhoc_cbor_map_head_length(size_t items);

/**
 * \brief Head length of a CBOR array, excluding the elements themselves.
 *
 * \param items                         Number of elements in the array.
 *
 * \return Number of bytes: 1, 2, 3, 5 or 9.
 */
size_t edhoc_cbor_array_head_length(size_t items);

/**
 * \brief Check whether a byte is a complete one byte CBOR integer.
 *
 *        RFC 9528: 3.3.2 represents such a byte string by that integer. Applies
 *        to connection identifiers and to a COSE 'kid'.
 *
 * \param value                         Byte to check.
 *
 * \return True if \p value encodes an integer in the range -24..23.
 */
bool edhoc_cbor_is_one_byte_int(uint8_t value);

/**
 * \brief Write the head of a CBOR byte string framing a payload of \p length
 *        bytes, so it can be streamed (e.g. into a hash) without a contiguous
 *        copy of the head and the payload.
 *
 * \param[out] head     Buffer of at least \ref EDHOC_CBOR_BSTR_HEAD_MAX_LEN
 *                      bytes receiving the head.
 * \param length        Length of the byte-string payload.
 *
 * \return Number of bytes written, zero on invalid arguments or on a payload
 *         longer than \c UINT32_MAX.
 */
size_t edhoc_cbor_bstr_head_write(uint8_t *head, size_t length);

/**@}*/

#endif /* EDHOC_CBOR_INTERNAL_H */
