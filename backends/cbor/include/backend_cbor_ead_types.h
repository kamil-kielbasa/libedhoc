/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_EAD_TYPES_H__
#define BACKEND_CBOR_EAD_TYPES_H__

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

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_EAD_TYPES_H__ */
