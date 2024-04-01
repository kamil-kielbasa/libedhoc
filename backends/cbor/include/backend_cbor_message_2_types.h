/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_MESSAGE_2_TYPES_H__
#define BACKEND_CBOR_MESSAGE_2_TYPES_H__

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

struct message_2 {
	struct zcbor_string _message_2_G_Y_CIPHERTEXT_2;
	union {
		struct zcbor_string _message_2_C_R_bstr;
		int32_t _message_2_C_R_int;
	};
	enum {
		_message_2_C_R_bstr,
		_message_2_C_R_int,
	} _message_2_C_R_choice;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_MESSAGE_2_TYPES_H__ */
