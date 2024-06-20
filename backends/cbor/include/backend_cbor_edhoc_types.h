/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_EDHOC_TYPES_H__
#define BACKEND_CBOR_EDHOC_TYPES_H__

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

struct ead {
	int32_t _ead_label;
	struct zcbor_string _ead_value;
	bool _ead_value_present;
};

struct ead_ {
	struct ead _ead[3];
	size_t _ead_count;
};

struct error {
	int32_t _error_ERR_CODE;
};

struct info {
	int32_t _info_label;
	struct zcbor_string _info_context;
	uint32_t _info_length;
};

struct suites_ {
	union {
		struct {
			int32_t _suites__int_int[3];
			size_t _suites__int_int_count;
		};
		int32_t _suites_int;
	};
	enum {
		_suites__int,
		_suites_int,
	} _suites_choice;
};

struct message_1 {
	int32_t _message_1_METHOD;
	struct suites_ _message_1_SUITES_I;
	struct zcbor_string _message_1_G_X;
	union {
		struct zcbor_string _message_1_C_I_bstr;
		int32_t _message_1_C_I_int;
	};
	enum {
		_message_1_C_I_bstr,
		_message_1_C_I_int,
	} _message_1_C_I_choice;
	struct ead_ _message_1_EAD_1;
	bool _message_1_EAD_1_present;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_EDHOC_TYPES_H__ */
