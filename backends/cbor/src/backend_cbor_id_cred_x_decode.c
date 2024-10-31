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
#include "backend_cbor_id_cred_x_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_repeated_id_cred_x_kid(zcbor_state_t *state, struct id_cred_x_kid_r *result);
static bool decode_COSE_X509(zcbor_state_t *state, struct COSE_X509_r *result);
static bool decode_repeated_id_cred_x_x5chain(zcbor_state_t *state, struct id_cred_x_x5chain *result);
static bool decode_COSE_CertHash(zcbor_state_t *state, struct COSE_CertHash *result);
static bool decode_repeated_id_cred_x_x5t(zcbor_state_t *state, struct id_cred_x_x5t *result);
static bool decode_id_cred_x(zcbor_state_t *state, struct id_cred_x *result);


static bool decode_repeated_id_cred_x_kid(
		zcbor_state_t *state, struct id_cred_x_kid_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).id_cred_x_kid_int)))) && (((*result).id_cred_x_kid_choice = id_cred_x_kid_int_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).id_cred_x_kid_bstr)))) && (((*result).id_cred_x_kid_choice = id_cred_x_kid_bstr_c), true))), zcbor_union_end_code(state), int_res))));

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

static bool decode_repeated_id_cred_x_x5chain(
		zcbor_state_t *state, struct id_cred_x_x5chain *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (33))))
	&& (decode_COSE_X509(state, (&(*result).id_cred_x_x5chain)))));

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

static bool decode_repeated_id_cred_x_x5t(
		zcbor_state_t *state, struct id_cred_x_x5t *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (34))))
	&& (decode_COSE_CertHash(state, (&(*result).id_cred_x_x5t)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_id_cred_x(
		zcbor_state_t *state, struct id_cred_x *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result).id_cred_x_kid_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_kid, state, (&(*result).id_cred_x_kid))
	&& zcbor_present_decode(&((*result).id_cred_x_x5chain_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_x5chain, state, (&(*result).id_cred_x_x5chain))
	&& zcbor_present_decode(&((*result).id_cred_x_x5t_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_x5t, state, (&(*result).id_cred_x_x5t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_id_cred_x(
		const uint8_t *payload, size_t payload_len,
		struct id_cred_x *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_id_cred_x, sizeof(states) / sizeof(zcbor_state_t), 1);
}
