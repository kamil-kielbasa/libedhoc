/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "backend_cbor_plaintext_2_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_map_kid(zcbor_state_t *state, const struct map_kid_r *input);
static bool encode_COSE_X509(zcbor_state_t *state, const struct COSE_X509_r *input);
static bool encode_repeated_map_x5chain(zcbor_state_t *state, const struct map_x5chain *input);
static bool encode_COSE_CertHash(zcbor_state_t *state, const struct COSE_CertHash *input);
static bool encode_repeated_map_x5t(zcbor_state_t *state, const struct map_x5t *input);
static bool encode_map(zcbor_state_t *state, const struct map *input);
static bool encode_ead_y(zcbor_state_t *state, const struct ead_y *input);
static bool encode_EAD_2(zcbor_state_t *state, const struct EAD_2 *input);
static bool encode_plaintext_2(zcbor_state_t *state, const struct plaintext_2 *input);


static bool encode_repeated_map_kid(
		zcbor_state_t *state, const struct map_kid_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (((*input).map_kid_choice == map_kid_int_c) ? ((zcbor_int32_encode(state, (&(*input).map_kid_int))))
	: (((*input).map_kid_choice == map_kid_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).map_kid_bstr))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_COSE_X509(
		zcbor_state_t *state, const struct COSE_X509_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).COSE_X509_choice == COSE_X509_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).COSE_X509_bstr))))
	: (((*input).COSE_X509_choice == COSE_X509_certs_l_c) ? ((zcbor_list_start_encode(state, 3) && ((zcbor_multi_encode_minmax(2, 3, &(*input).COSE_X509_certs_l_certs_count, (zcbor_encoder_t *)zcbor_bstr_encode, state, (&(*input).COSE_X509_certs_l_certs), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3)))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_map_x5chain(
		zcbor_state_t *state, const struct map_x5chain *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (33))))
	&& (encode_COSE_X509(state, (&(*input).map_x5chain)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_COSE_CertHash(
		zcbor_state_t *state, const struct COSE_CertHash *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_encode(state, 2) && ((((((*input).COSE_CertHash_hashAlg_choice == COSE_CertHash_hashAlg_int_c) ? ((zcbor_int32_encode(state, (&(*input).COSE_CertHash_hashAlg_int))))
	: (((*input).COSE_CertHash_hashAlg_choice == COSE_CertHash_hashAlg_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).COSE_CertHash_hashAlg_tstr))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input).COSE_CertHash_hashValue))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_map_x5t(
		zcbor_state_t *state, const struct map_x5t *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (34))))
	&& (encode_COSE_CertHash(state, (&(*input).map_x5t)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_map(
		zcbor_state_t *state, const struct map *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 3) && (((!(*input).map_kid_present || encode_repeated_map_kid(state, (&(*input).map_kid)))
	&& (!(*input).map_x5chain_present || encode_repeated_map_x5chain(state, (&(*input).map_x5chain)))
	&& (!(*input).map_x5t_present || encode_repeated_map_x5t(state, (&(*input).map_x5t)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_ead_y(
		zcbor_state_t *state, const struct ead_y *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input).ead_y_ead_label))))
	&& (!(*input).ead_y_ead_value_present || zcbor_bstr_encode(state, (&(*input).ead_y_ead_value))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_EAD_2(
		zcbor_state_t *state, const struct EAD_2 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_encode_minmax(1, 3, &(*input).EAD_2_count, (zcbor_encoder_t *)encode_ead_y, state, (&(*input).EAD_2), sizeof(struct ead_y)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_plaintext_2(
		zcbor_state_t *state, const struct plaintext_2 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((((*input).plaintext_2_C_R_choice == plaintext_2_C_R_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).plaintext_2_C_R_bstr))))
	: (((*input).plaintext_2_C_R_choice == plaintext_2_C_R_int_c) ? (((((*input).plaintext_2_C_R_int >= -24)
	&& ((*input).plaintext_2_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input).plaintext_2_C_R_int))))
	: false)))
	&& ((((*input).plaintext_2_ID_CRED_R_choice == plaintext_2_ID_CRED_R_int_c) ? ((zcbor_int32_encode(state, (&(*input).plaintext_2_ID_CRED_R_int))))
	: (((*input).plaintext_2_ID_CRED_R_choice == plaintext_2_ID_CRED_R_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).plaintext_2_ID_CRED_R_bstr))))
	: (((*input).plaintext_2_ID_CRED_R_choice == plaintext_2_ID_CRED_R_map_m_c) ? ((encode_map(state, (&(*input).plaintext_2_ID_CRED_R_map_m))))
	: false))))
	&& ((zcbor_bstr_encode(state, (&(*input).plaintext_2_Signature_or_MAC_2))))
	&& (!(*input).plaintext_2_EAD_2_m_present || encode_EAD_2(state, (&(*input).plaintext_2_EAD_2_m))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_plaintext_2(
		uint8_t *payload, size_t payload_len,
		const struct plaintext_2 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_plaintext_2, sizeof(states) / sizeof(zcbor_state_t), 9);
}
