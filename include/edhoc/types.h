/**
 * \file    types.h
 * \author  Kamil Kielbasa
 * \brief   Public EDHOC protocol types.
 *
 *          Method, connection-identifier and error types exchanged across the
 *          public API. The \c edhoc_context handle itself is opaque and is
 *          forward-declared in \c <edhoc/edhoc.h>; its layout is
 *          library-internal.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_TYPES_H
#define EDHOC_TYPES_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */

#ifndef CONFIG_LIBEDHOC_ENABLE
#error "Library has not been enabled."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID
#error "Lack of defined maximum length of connection identifier in bytes."
#endif

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-types EDHOC types
 * @{
 */

/**
 * \brief RFC 9528: 3.2. Method.
 */
enum edhoc_method {
	/** Initiator signature key, Responder signature key. */
	EDHOC_METHOD_0 = 0,
	/** Initiator signature key, Responder static DH key. */
	EDHOC_METHOD_1 = 1,
	/** Initiator static DH key, Responder signature key. */
	EDHOC_METHOD_2 = 2,
	/** Initiator static DH key, Responder static DH key. */
	EDHOC_METHOD_3 = 3,
	/** Sentinel: number of methods, not a valid method value. */
	EDHOC_METHOD_MAX,
};

/**
 * \brief EDHOC connection identifier encoding type (RFC 9528: 3.3.2).
 */
enum edhoc_connection_id_type {
	/** Encode connection identifier as CBOR integer. */
	EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
	/** Encode connection identifier as CBOR byte string. */
	EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
};

/**
 * \brief RFC 9528: 3.3.2. Representation of Byte String Identifiers.
 */
struct edhoc_connection_id {
	/** Encoding of the connection identifier. It must follow the
	 *  representation of byte string identifiers described in RFC 9528:
	 *  3.3.2. */
	enum edhoc_connection_id_type encode_type;

	/** Connection identifier as a CBOR integer. */
	int8_t int_value;

	/** Connection identifier as a CBOR byte string. */
	uint8_t bstr_value[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID + 1];
	/** Number of valid bytes in \p bstr_value. */
	size_t bstr_length;
};

/**
 * \brief EDHOC error code. RFC 9528: 6. Error Handling.
 */
enum edhoc_error_code {
	/** RFC 9528: 6.1. Success. */
	EDHOC_ERROR_CODE_SUCCESS = 0,
	/** RFC 9528: 6.2. Unspecified Error. */
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR = 1,
	/** RFC 9528: 6.3. Wrong Selected Cipher Suite. */
	EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE = 2,
	/** RFC 9528: 6.4. Unknown Credential Referenced. */
	EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED = 3,
};

/**
 * \brief EDHOC error information. RFC 9528: 6. Error Handling.
 */
struct edhoc_error_info {
	union {
		/** Caller-owned buffer for the diagnostic text of
		 *  \ref EDHOC_ERROR_CODE_UNSPECIFIED_ERROR. Not \c const: on
		 *  processing the library writes the received text into it. */
		char *text_string;
		/** Caller-owned buffer for the suites of
		 *  \ref EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE. */
		int32_t *cipher_suites;
	};

	/** Capacity of \p text_string or \p cipher_suites, in entries. */
	size_t entries_size;
	/** Number of valid entries in \p text_string or \p cipher_suites (set by
	 *  the caller on compose, by the library on process). */
	size_t entries_length;
};

/**@}*/

#endif /* EDHOC_TYPES_H */
