/*
 * Generated using zcbor version 0.8.1
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

struct info {
	int32_t info_label;
	struct zcbor_string info_context;
	uint32_t info_length;
};

struct ead_x {
	int32_t ead_x_ead_label;
	struct zcbor_string ead_x_ead_value;
	bool ead_x_ead_value_present;
};

struct ead {
	struct ead_x ead[3];
	size_t ead_count;
};

struct suites_r {
	union {
		struct {
			int32_t suites_int_l_int[3];
			size_t suites_int_l_int_count;
		};
		int32_t suites_int;
	};
	enum {
		suites_int_l_c,
		suites_int_c,
	} suites_choice;
};

struct message_error_ERR_INFO_r {
	union {
		struct zcbor_string message_error_ERR_INFO_tstr;
		struct suites_r message_error_ERR_INFO_suites_m;
	};
	enum {
		message_error_ERR_INFO_tstr_c,
		message_error_ERR_INFO_suites_m_c,
		message_error_ERR_INFO_bool_c,
	} message_error_ERR_INFO_choice;
};

struct message_error {
	int32_t message_error_ERR_CODE;
	struct message_error_ERR_INFO_r message_error_ERR_INFO;
	bool message_error_ERR_INFO_present;
};

struct EAD_1 {
	struct ead_x EAD_1[3];
	size_t EAD_1_count;
};

struct message_1 {
	int32_t message_1_METHOD;
	struct suites_r message_1_SUITES_I;
	struct zcbor_string message_1_G_X;
	union {
		struct zcbor_string message_1_C_I_bstr;
		int32_t message_1_C_I_int;
	};
	enum {
		message_1_C_I_bstr_c,
		message_1_C_I_int_c,
	} message_1_C_I_choice;
	struct EAD_1 message_1_EAD_1_m;
	bool message_1_EAD_1_m_present;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_EDHOC_TYPES_H__ */
