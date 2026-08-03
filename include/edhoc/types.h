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

/* EDHOC headers: */
#include <edhoc/values.h>

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
 * \brief EDHOC message number (RFC 9528: 5).
 */
enum edhoc_message {
	/** EDHOC message 1. */
	EDHOC_MESSAGE_1,
	/** EDHOC message 2. */
	EDHOC_MESSAGE_2,
	/** EDHOC message 3. */
	EDHOC_MESSAGE_3,
	/** EDHOC message 4. */
	EDHOC_MESSAGE_4,
};

/**
 * \brief EDHOC role of the local peer (RFC 9528: 3.1).
 */
enum edhoc_role {
	/** The local peer sent message 1. */
	EDHOC_ROLE_INITIATOR,
	/** The local peer received message 1. */
	EDHOC_ROLE_RESPONDER,
};

/**
 * \brief Immutable view of a byte sequence.
 */
struct edhoc_buffer {
	/** Start of the byte sequence. */
	const uint8_t *value;
	/** Number of bytes in \p value. */
	size_t length;
};

/**
 * \brief Encoding of a CBOR item that is either a number or a string.
 */
enum edhoc_encode_type {
	/** CBOR integer. */
	EDHOC_ENCODE_TYPE_INTEGER,
	/** CBOR byte string or text string, depending on the field: COSE 'kid'
	 *  is a bstr, hashAlg in COSE_CertHash is a tstr. */
	EDHOC_ENCODE_TYPE_STRING,
};

/**
 * \brief A CBOR item that is either a number or a string.
 */
struct edhoc_cbor_int_or_string {
	/** Which member of the union is valid. */
	enum edhoc_encode_type encode_type;

	union {
		/** Valid for #EDHOC_ENCODE_TYPE_INTEGER. */
		int32_t integer;
		/** Valid for #EDHOC_ENCODE_TYPE_STRING. */
		struct edhoc_buffer string;
	};
};

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
 * \brief Context of a call from the library into an application callback.
 *
 * Valid for the duration of the callback.
 */
struct edhoc_call_context {
	/** Role of the local peer. */
	enum edhoc_role role;
	/** Negotiated method. */
	enum edhoc_method method;
	/** Selected cipher suite. */
	int32_t selected_cipher_suite;
	/** Message being composed or processed. */
	enum edhoc_message message;
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

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**@}*/

#endif /* EDHOC_TYPES_H */
