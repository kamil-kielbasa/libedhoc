/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_X509_TYPES_H__
#define BACKEND_CBOR_X509_TYPES_H__

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

struct COSE_X509_ {
	union {
		struct zcbor_string _COSE_X509_bstr;
		struct {
			struct zcbor_string _COSE_X509__certs_certs[3];
			size_t _COSE_X509__certs_certs_count;
		};
	};
	enum {
		_COSE_X509_bstr,
		_COSE_X509__certs,
	} _COSE_X509_choice;
};

struct id_cred_x_x5chain {
	struct COSE_X509_ _id_cred_x_x5chain;
};

struct COSE_CertHash {
	union {
		int32_t _COSE_CertHash_hashAlg_int;
		struct zcbor_string _COSE_CertHash_hashAlg_tstr;
	};
	enum {
		_COSE_CertHash_hashAlg_int,
		_COSE_CertHash_hashAlg_tstr,
	} _COSE_CertHash_hashAlg_choice;
	struct zcbor_string _COSE_CertHash_hashValue;
};

struct id_cred_x_x5t {
	struct COSE_CertHash _id_cred_x_x5t;
};

struct id_cred_x {
	struct id_cred_x_kid_ _id_cred_x_kid;
	bool _id_cred_x_kid_present;
	struct id_cred_x_x5chain _id_cred_x_x5chain;
	bool _id_cred_x_x5chain_present;
	struct id_cred_x_x5t _id_cred_x_x5t;
	bool _id_cred_x_x5t_present;
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

struct plaintext_4_EAD_4 {
	struct ead_x_ _plaintext_4_EAD_4;
	bool _plaintext_4_EAD_4_present;
};

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

struct map_x5chain {
	struct COSE_X509_ _map_x5chain;
};

struct map_x5t {
	struct COSE_CertHash _map_x5t;
};

struct map {
	struct map_kid_ _map_kid;
	bool _map_kid_present;
	struct map_x5chain _map_x5chain;
	bool _map_x5chain_present;
	struct map_x5t _map_x5t;
	bool _map_x5t_present;
};

struct plaintext_2 {
	union {
		struct zcbor_string _plaintext_2_C_R_bstr;
		int32_t _plaintext_2_C_R_int;
	};
	enum {
		_plaintext_2_C_R_bstr,
		_plaintext_2_C_R_int,
	} _plaintext_2_C_R_choice;
	union {
		int32_t _plaintext_2_ID_CRED_R_int;
		struct zcbor_string _plaintext_2_ID_CRED_R_bstr;
		struct map _plaintext_2_ID_CRED_R__map;
	};
	enum {
		_plaintext_2_ID_CRED_R_int,
		_plaintext_2_ID_CRED_R_bstr,
		_plaintext_2_ID_CRED_R__map,
	} _plaintext_2_ID_CRED_R_choice;
	struct zcbor_string _plaintext_2_Signature_or_MAC_2;
	struct ead_x_ _plaintext_2_EAD_2;
	bool _plaintext_2_EAD_2_present;
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

#endif /* BACKEND_CBOR_X509_TYPES_H__ */
