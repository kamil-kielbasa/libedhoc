/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_ID_CRED_X_TYPES_H__
#define BACKEND_CBOR_ID_CRED_X_TYPES_H__

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

struct id_cred_x_kid_ {
	union {
		int32_t _id_cred_x_kid_int;
		struct zcbor_string _id_cred_x_kid_bstr;
	};
	enum {
		_id_cred_x_kid_int,
		_id_cred_x_kid_bstr,
	} _id_cred_x_kid_choice;
};

struct id_cred_x_x5bag {
	struct zcbor_string _id_cred_x_x5bag;
};

struct id_cred_x_x5chain {
	struct zcbor_string _id_cred_x_x5chain;
};

struct id_cred_x_x5t_ {
	union {
		int32_t _id_cred_x_x5t_alg_int;
		struct zcbor_string _id_cred_x_x5t_alg_bstr;
	};
	enum {
		_id_cred_x_x5t_alg_int,
		_id_cred_x_x5t_alg_bstr,
	} _id_cred_x_x5t_alg_choice;
	struct zcbor_string _id_cred_x_x5t_hash;
};

struct id_cred_x {
	struct id_cred_x_kid_ _id_cred_x_kid;
	bool _id_cred_x_kid_present;
	struct id_cred_x_x5bag _id_cred_x_x5bag;
	bool _id_cred_x_x5bag_present;
	struct id_cred_x_x5chain _id_cred_x_x5chain;
	bool _id_cred_x_x5chain_present;
	struct id_cred_x_x5t_ _id_cred_x_x5t;
	bool _id_cred_x_x5t_present;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_ID_CRED_X_TYPES_H__ */
