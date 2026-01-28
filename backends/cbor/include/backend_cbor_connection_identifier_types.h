/*
 * Generated using zcbor version 0.9.1-9b07780
 * https://github.com/NordicSemiconductor/zcbor
 * at: 2026-01-27 07:10:10
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_CONNECTION_IDENTIFIER_TYPES_H__
#define BACKEND_CBOR_CONNECTION_IDENTIFIER_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct connection_identifier_r {
	union {
		struct zcbor_string connection_identifier_bstr;
		int32_t connection_identifier_int;
	};
	enum {
		connection_identifier_bstr_c,
		connection_identifier_int_c,
	} connection_identifier_choice;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_CONNECTION_IDENTIFIER_TYPES_H__ */

