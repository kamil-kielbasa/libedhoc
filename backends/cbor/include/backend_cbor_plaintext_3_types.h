/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_PLAINTEXT_3_TYPES_H__
#define BACKEND_CBOR_PLAINTEXT_3_TYPES_H__

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

struct map_kid_ {
	union {
		int32_t _map_kid_int;
		struct zcbor_string _map_kid_bstr;
	};
	enum {
		_map_kid_int,
		_map_kid_bstr,
	} _map_kid_choice;
};

struct map_x5bag {
	struct zcbor_string _map_x5bag;
};

struct map_x5chain {
	struct zcbor_string _map_x5chain;
};

struct map_x5t_ {
	union {
		int32_t _map_x5t_alg_int;
		struct zcbor_string _map_x5t_alg_bstr;
	};
	enum {
		_map_x5t_alg_int,
		_map_x5t_alg_bstr,
	} _map_x5t_alg_choice;
	struct zcbor_string _map_x5t_hash;
};

struct map {
	struct map_kid_ _map_kid;
	bool _map_kid_present;
	struct map_x5bag _map_x5bag;
	bool _map_x5bag_present;
	struct map_x5chain _map_x5chain;
	bool _map_x5chain_present;
	struct map_x5t_ _map_x5t;
	bool _map_x5t_present;
};

struct ead_x {
	int32_t _ead_x_ead_label;
	struct zcbor_string _ead_x_ead_value;
	bool _ead_x_ead_value_present;
};

struct ead_x_ {
	struct ead_x _ead_x[3];
	size_t _ead_x_count;
};

struct plaintext_3 {
	union {
		int32_t _plaintext_3_ID_CRED_I_int;
		struct zcbor_string _plaintext_3_ID_CRED_I_bstr;
		struct map _plaintext_3_ID_CRED_I__map;
	};
	enum {
		_plaintext_3_ID_CRED_I_int,
		_plaintext_3_ID_CRED_I_bstr,
		_plaintext_3_ID_CRED_I__map,
	} _plaintext_3_ID_CRED_I_choice;
	struct zcbor_string _plaintext_3_Signature_or_MAC_3;
	struct ead_x_ _plaintext_3_EAD_3;
	bool _plaintext_3_EAD_3_present;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_PLAINTEXT_3_TYPES_H__ */
