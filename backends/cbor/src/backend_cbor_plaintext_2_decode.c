/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "backend_cbor_plaintext_2_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_repeated_map_kid(zcbor_state_t *state, struct map_kid_r *result);
static bool decode_COSE_X509(zcbor_state_t *state, struct COSE_X509_r *result);
static bool decode_repeated_map_x5chain(zcbor_state_t *state, struct map_x5chain *result);
static bool decode_COSE_CertHash(zcbor_state_t *state, struct COSE_CertHash *result);
static bool decode_repeated_map_x5t(zcbor_state_t *state, struct map_x5t *result);
static bool decode_map(zcbor_state_t *state, struct map *result);
static bool decode_ead_y(zcbor_state_t *state, struct ead_y *result);
static bool decode_EAD_2(zcbor_state_t *state, struct EAD_2 *result);
static bool decode_plaintext_2(zcbor_state_t *state, struct plaintext_2 *result);


static bool decode_repeated_map_kid(
		zcbor_state_t *state, struct map_kid_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).map_kid_int)))) && (((*result).map_kid_choice = map_kid_int_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).map_kid_bstr)))) && (((*result).map_kid_choice = map_kid_bstr_c), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_COSE_X509(
		zcbor_state_t *state, struct COSE_X509_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).COSE_X509_bstr)))) && (((*result).COSE_X509_choice = COSE_X509_bstr_c), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, 3, &(*result).COSE_X509_certs_l_certs_count, (zcbor_decoder_t *)zcbor_bstr_decode, state, (&(*result).COSE_X509_certs_l_certs), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))) && (((*result).COSE_X509_choice = COSE_X509_certs_l_c), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_map_x5chain(
		zcbor_state_t *state, struct map_x5chain *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (33))))
	&& (decode_COSE_X509(state, (&(*result).map_x5chain)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_COSE_CertHash(
		zcbor_state_t *state, struct COSE_CertHash *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).COSE_CertHash_hashAlg_int)))) && (((*result).COSE_CertHash_hashAlg_choice = COSE_CertHash_hashAlg_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).COSE_CertHash_hashAlg_tstr)))) && (((*result).COSE_CertHash_hashAlg_choice = COSE_CertHash_hashAlg_tstr_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result).COSE_CertHash_hashValue))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_map_x5t(
		zcbor_state_t *state, struct map_x5t *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (34))))
	&& (decode_COSE_CertHash(state, (&(*result).map_x5t)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_map(
		zcbor_state_t *state, struct map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result).map_kid_present), (zcbor_decoder_t *)decode_repeated_map_kid, state, (&(*result).map_kid))
	&& zcbor_present_decode(&((*result).map_x5chain_present), (zcbor_decoder_t *)decode_repeated_map_x5chain, state, (&(*result).map_x5chain))
	&& zcbor_present_decode(&((*result).map_x5t_present), (zcbor_decoder_t *)decode_repeated_map_x5t, state, (&(*result).map_x5t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_ead_y(
		zcbor_state_t *state, struct ead_y *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result).ead_y_ead_label))))
	&& ((*result).ead_y_ead_value_present = ((zcbor_bstr_decode(state, (&(*result).ead_y_ead_value)))), 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_EAD_2(
		zcbor_state_t *state, struct EAD_2 *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result).EAD_2_count, (zcbor_decoder_t *)decode_ead_y, state, (&(*result).EAD_2), sizeof(struct ead_y)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_plaintext_2(
		zcbor_state_t *state, struct plaintext_2 *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).plaintext_2_C_R_bstr)))) && (((*result).plaintext_2_C_R_choice = plaintext_2_C_R_bstr_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).plaintext_2_C_R_int)))
	&& ((((*result).plaintext_2_C_R_int >= -24)
	&& ((*result).plaintext_2_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result).plaintext_2_C_R_choice = plaintext_2_C_R_int_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).plaintext_2_ID_CRED_R_int)))) && (((*result).plaintext_2_ID_CRED_R_choice = plaintext_2_ID_CRED_R_int_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).plaintext_2_ID_CRED_R_bstr)))) && (((*result).plaintext_2_ID_CRED_R_choice = plaintext_2_ID_CRED_R_bstr_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_map(state, (&(*result).plaintext_2_ID_CRED_R_map_m)))) && (((*result).plaintext_2_ID_CRED_R_choice = plaintext_2_ID_CRED_R_map_m_c), true)))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result).plaintext_2_Signature_or_MAC_2))))
	&& ((*result).plaintext_2_EAD_2_m_present = ((decode_EAD_2(state, (&(*result).plaintext_2_EAD_2_m)))), 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_plaintext_2(
		const uint8_t *payload, size_t payload_len,
		struct plaintext_2 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_plaintext_2, sizeof(states) / sizeof(zcbor_state_t), 9);
}
