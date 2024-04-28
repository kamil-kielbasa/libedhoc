/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_PLAINTEXT_4_TYPES_H__
#define BACKEND_CBOR_PLAINTEXT_4_TYPES_H__

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

struct ead_x {
	int32_t _ead_x_ead_label;
	struct zcbor_string _ead_x_ead_value;
	bool _ead_x_ead_value_present;
};

struct ead_x_ {
	struct ead_x _ead_x[3];
	size_t _ead_x_count;
};

struct plaintext_4_EAD_4 {
	struct ead_x_ _plaintext_4_EAD_4;
	bool _plaintext_4_EAD_4_present;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_PLAINTEXT_4_TYPES_H__ */
