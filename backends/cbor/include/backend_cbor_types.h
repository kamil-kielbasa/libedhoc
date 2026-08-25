/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_TYPES_H__
#define BACKEND_CBOR_TYPES_H__

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

struct sig_structure {
	struct zcbor_string sig_structure_protected;
	struct zcbor_string sig_structure_external_aad;
	struct zcbor_string sig_structure_payload;
};

struct enc_structure {
	struct zcbor_string enc_structure_protected;
	struct zcbor_string enc_structure_external_aad;
};

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
	struct ead message_1_ead_m;
	bool message_1_ead_m_present;
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
		struct id_cred_x plaintext_2_ID_CRED_R_id_cred_x_m;
	};
	enum {
		plaintext_2_ID_CRED_R_int_c,
		plaintext_2_ID_CRED_R_bstr_c,
		plaintext_2_ID_CRED_R_id_cred_x_m_c,
	} plaintext_2_ID_CRED_R_choice;
	struct zcbor_string plaintext_2_Signature_or_MAC_2;
	struct ead plaintext_2_ead_m;
	bool plaintext_2_ead_m_present;
};

struct plaintext_3 {
	union {
		int32_t plaintext_3_ID_CRED_I_int;
		struct zcbor_string plaintext_3_ID_CRED_I_bstr;
		struct id_cred_x plaintext_3_ID_CRED_I_id_cred_x_m;
	};
	enum {
		plaintext_3_ID_CRED_I_int_c,
		plaintext_3_ID_CRED_I_bstr_c,
		plaintext_3_ID_CRED_I_id_cred_x_m_c,
	} plaintext_3_ID_CRED_I_choice;
	struct zcbor_string plaintext_3_Signature_or_MAC_3;
	struct ead plaintext_3_ead_m;
	bool plaintext_3_ead_m_present;
};

struct plaintext_4 {
	struct ead plaintext_4;
	bool plaintext_4_present;
};

struct plaintext_2a {
	union {
		struct zcbor_string plaintext_2a_C_R_bstr;
		int32_t plaintext_2a_C_R_int;
	};
	enum {
		plaintext_2a_C_R_bstr_c,
		plaintext_2a_C_R_int_c,
	} plaintext_2a_C_R_choice;
	struct ead plaintext_2a_ead_m;
	bool plaintext_2a_ead_m_present;
};

struct plaintext_3a {
	union {
		int32_t plaintext_3a_ID_CRED_PSK_int;
		struct zcbor_string plaintext_3a_ID_CRED_PSK_bstr;
		struct id_cred_x plaintext_3a_ID_CRED_PSK_id_cred_x_m;
	};
	enum {
		plaintext_3a_ID_CRED_PSK_int_c,
		plaintext_3a_ID_CRED_PSK_bstr_c,
		plaintext_3a_ID_CRED_PSK_id_cred_x_m_c,
	} plaintext_3a_ID_CRED_PSK_choice;
	struct zcbor_string plaintext_3a_CIPHERTEXT_3B;
};

struct plaintext_3b {
	struct ead plaintext_3b;
	bool plaintext_3b_present;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_TYPES_H__ */
