/**
 * \file    edhoc_cbor_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC CBOR utilities implementation.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC internal headers: */
#include "edhoc_cbor_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Module defines ---------------------------------------------------------- */

/** Largest argument carried by the initial byte alone (RFC 8949: 3). */
#define EDHOC_CBOR_ARG_IMMEDIATE_MAX ((size_t)23)

/** Head lengths by argument width (RFC 8949: 3). */
#define EDHOC_CBOR_HEAD_LEN_IMMEDIATE ((size_t)1)
#define EDHOC_CBOR_HEAD_LEN_UINT8 ((size_t)2)
#define EDHOC_CBOR_HEAD_LEN_UINT16 ((size_t)3)
#define EDHOC_CBOR_HEAD_LEN_UINT32 ((size_t)5)
#define EDHOC_CBOR_HEAD_LEN_UINT64 ((size_t)9)

/** Initial byte of a byte string head, by argument width (RFC 8949: 3.1). */
#define EDHOC_CBOR_BSTR_IB_IMMEDIATE ((uint8_t)0x40u)
#define EDHOC_CBOR_BSTR_IB_UINT8 ((uint8_t)0x58u)
#define EDHOC_CBOR_BSTR_IB_UINT16 ((uint8_t)0x59u)
#define EDHOC_CBOR_BSTR_IB_UINT32 ((uint8_t)0x5Au)

/** Byte mask and shift used when splitting an argument into bytes. */
#define EDHOC_CBOR_BYTE_MASK ((size_t)0xFFu)
#define EDHOC_CBOR_BITS_PER_BYTE (8u)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Head length for a CBOR argument.
 *
 *        RFC 8949: 3 encodes the argument the same way for every major type,
 *        so a length, an item count and an integer all share this ladder.
 *
 * \param argument              Argument value.
 *
 * \return Number of head bytes.
 */
STATIC size_t comp_head_length(size_t argument);

/* Static function definitions --------------------------------------------- */

STATIC size_t comp_head_length(size_t argument)
{
	if (argument <= EDHOC_CBOR_ARG_IMMEDIATE_MAX) {
		return EDHOC_CBOR_HEAD_LEN_IMMEDIATE;
	} else if (argument <= UINT8_MAX) {
		return EDHOC_CBOR_HEAD_LEN_UINT8;
	} else if (argument <= UINT16_MAX) {
		return EDHOC_CBOR_HEAD_LEN_UINT16;
	} else if (argument <= UINT32_MAX) {
		return EDHOC_CBOR_HEAD_LEN_UINT32;
	} else {
		return EDHOC_CBOR_HEAD_LEN_UINT64;
	}
}

/* Module interface function definitions ----------------------------------- */

size_t edhoc_cbor_int_head_length(int32_t value)
{
	/* RFC 8949: 3. A negative integer carries the argument -1 - n. */
	const size_t argument = (0 <= value) ? (size_t)value :
					       (size_t)(-1 - value);

	return comp_head_length(argument);
}

size_t edhoc_cbor_tstr_head_length(size_t length)
{
	return comp_head_length(length);
}

size_t edhoc_cbor_bstr_head_length(size_t length)
{
	return comp_head_length(length);
}

size_t edhoc_cbor_map_head_length(size_t items)
{
	return comp_head_length(items);
}

size_t edhoc_cbor_array_head_length(size_t items)
{
	return comp_head_length(items);
}

bool edhoc_cbor_is_one_byte_int(uint8_t value)
{
	const uint8_t cbor_unsigned_max = 0x17u;
	const uint8_t cbor_negative_min = 0x20u;
	const uint8_t cbor_negative_max = 0x37u;

	return value <= cbor_unsigned_max ||
	       (cbor_negative_min <= value && value <= cbor_negative_max);
}

size_t edhoc_cbor_bstr_head_write(uint8_t *head, size_t length)
{
	if (NULL == head ||
	    EDHOC_CBOR_BSTR_HEAD_MAX_LEN < comp_head_length(length)) {
		EDHOC_LOG_ERR("Invalid arguments");
		return 0;
	}

	if (length <= EDHOC_CBOR_ARG_IMMEDIATE_MAX) {
		head[0] = (uint8_t)(EDHOC_CBOR_BSTR_IB_IMMEDIATE | length);
		return EDHOC_CBOR_HEAD_LEN_IMMEDIATE;
	}

	if (length <= UINT8_MAX) {
		head[0] = EDHOC_CBOR_BSTR_IB_UINT8;
		head[1] = (uint8_t)length;
		return EDHOC_CBOR_HEAD_LEN_UINT8;
	}

	if (length <= UINT16_MAX) {
		head[0] = EDHOC_CBOR_BSTR_IB_UINT16;
		head[1] = (uint8_t)(length >> EDHOC_CBOR_BITS_PER_BYTE);
		head[2] = (uint8_t)(length & EDHOC_CBOR_BYTE_MASK);
		return EDHOC_CBOR_HEAD_LEN_UINT16;
	}

	head[0] = EDHOC_CBOR_BSTR_IB_UINT32;
	head[1] = (uint8_t)(length >> (3u * EDHOC_CBOR_BITS_PER_BYTE));
	head[2] = (uint8_t)(length >> (2u * EDHOC_CBOR_BITS_PER_BYTE));
	head[3] = (uint8_t)(length >> EDHOC_CBOR_BITS_PER_BYTE);
	head[4] = (uint8_t)(length & EDHOC_CBOR_BYTE_MASK);

	return EDHOC_CBOR_HEAD_LEN_UINT32;
}
