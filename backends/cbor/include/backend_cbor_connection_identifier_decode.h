/*
 * Generated using zcbor version 0.9.1-9b07780
 * https://github.com/NordicSemiconductor/zcbor
 * at: 2026-01-27 07:10:10
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_CONNECTION_IDENTIFIER_DECODE_H__
#define BACKEND_CBOR_CONNECTION_IDENTIFIER_DECODE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "backend_cbor_connection_identifier_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max-qty than this file"
#endif


int cbor_decode_connection_identifier(
		const uint8_t *payload, size_t payload_len,
		struct connection_identifier_r *result,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_CONNECTION_IDENTIFIER_DECODE_H__ */

