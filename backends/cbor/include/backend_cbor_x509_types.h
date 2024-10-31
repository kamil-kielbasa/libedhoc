/*
 * Generated using zcbor version 0.8.1
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

struct id_cred_x_kid_r {
	union {
		int32_t id_cred_x_kid_int;
		struct zcbor_string id_cred_x_kid_bstr;
	};
	enum {
		id_cred_x_kid_int_c,
		id_cred_x_kid_bstr_c,
	} id_cred_x_kid_choice;
};

struct COSE_X509_r {
	union {
		struct zcbor_string COSE_X509_bstr;
		struct {
			struct zcbor_string COSE_X509_certs_l_certs[3];
			size_t COSE_X509_certs_l_certs_count;
		};
	};
	enum {
		COSE_X509_bstr_c,
		COSE_X509_certs_l_c,
	} COSE_X509_choice;
};

struct id_cred_x_x5chain {
	struct COSE_X509_r id_cred_x_x5chain;
};

struct COSE_CertHash {
	union {
		int32_t COSE_CertHash_hashAlg_int;
		struct zcbor_string COSE_CertHash_hashAlg_tstr;
	};
	enum {
		COSE_CertHash_hashAlg_int_c,
		COSE_CertHash_hashAlg_tstr_c,
	} COSE_CertHash_hashAlg_choice;
	struct zcbor_string COSE_CertHash_hashValue;
};

struct id_cred_x_x5t {
	struct COSE_CertHash id_cred_x_x5t;
};

struct id_cred_x {
	struct id_cred_x_kid_r id_cred_x_kid;
	bool id_cred_x_kid_present;
	struct id_cred_x_x5chain id_cred_x_x5chain;
	bool id_cred_x_x5chain_present;
	struct id_cred_x_x5t id_cred_x_x5t;
	bool id_cred_x_x5t_present;
};

struct map_kid_r {
	union {
		int32_t map_kid_int;
		struct zcbor_string map_kid_bstr;
	};
	enum {
		map_kid_int_c,
		map_kid_bstr_c,
	} map_kid_choice;
};

struct map_x5chain {
	struct COSE_X509_r map_x5chain;
};

struct map_x5t {
	struct COSE_CertHash map_x5t;
};

struct map {
	struct map_kid_r map_kid;
	bool map_kid_present;
	struct map_x5chain map_x5chain;
	bool map_x5chain_present;
	struct map_x5t map_x5t;
	bool map_x5t_present;
};

struct ead_y {
	int32_t ead_y_ead_label;
	struct zcbor_string ead_y_ead_value;
	bool ead_y_ead_value_present;
};

struct EAD_2 {
	struct ead_y EAD_2[3];
	size_t EAD_2_count;
};

struct plaintext_2 {
	union {
		struct zcbor_string plaintext_2_C_R_bstr;
		int32_t plaintext_2_C_R_int;
	};
	enum {
		plaintext_2_C_R_bstr_c,
		plaintext_2_C_R_int_c,
	} plaintext_2_C_R_choice;
	union {
		int32_t plaintext_2_ID_CRED_R_int;
		struct zcbor_string plaintext_2_ID_CRED_R_bstr;
		struct map plaintext_2_ID_CRED_R_map_m;
	};
	enum {
		plaintext_2_ID_CRED_R_int_c,
		plaintext_2_ID_CRED_R_bstr_c,
		plaintext_2_ID_CRED_R_map_m_c,
	} plaintext_2_ID_CRED_R_choice;
	struct zcbor_string plaintext_2_Signature_or_MAC_2;
	struct EAD_2 plaintext_2_EAD_2_m;
	bool plaintext_2_EAD_2_m_present;
};

struct EAD_3 {
	struct ead_y EAD_3[3];
	size_t EAD_3_count;
};

struct plaintext_3 {
	union {
		int32_t plaintext_3_ID_CRED_I_int;
		struct zcbor_string plaintext_3_ID_CRED_I_bstr;
		struct map plaintext_3_ID_CRED_I_map_m;
	};
	enum {
		plaintext_3_ID_CRED_I_int_c,
		plaintext_3_ID_CRED_I_bstr_c,
		plaintext_3_ID_CRED_I_map_m_c,
	} plaintext_3_ID_CRED_I_choice;
	struct zcbor_string plaintext_3_Signature_or_MAC_3;
	struct EAD_3 plaintext_3_EAD_3_m;
	bool plaintext_3_EAD_3_m_present;
};

struct EAD_4 {
	struct ead_y EAD_4[3];
	size_t EAD_4_count;
};

struct plaintext_4 {
	struct EAD_4 plaintext_4;
	bool plaintext_4_present;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_X509_TYPES_H__ */
