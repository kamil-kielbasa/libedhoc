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
#include "backend_cbor_header_map_decode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_repeated_Generic_Headers_uint1union(zcbor_state_t *state, struct Generic_Headers_uint1union_r *result);
static bool decode_label(zcbor_state_t *state, struct label_r *result);
static bool decode_repeated_Generic_Headers_label_m_l(zcbor_state_t *state, struct Generic_Headers_label_m_l_r *result);
static bool decode_repeated_Generic_Headers_uint3union(zcbor_state_t *state, struct Generic_Headers_uint3union_r *result);
static bool decode_repeated_Generic_Headers_uint4bstr(zcbor_state_t *state, struct Generic_Headers_uint4bstr *result);
static bool decode_repeated_Generic_Headers_uint5bstr(zcbor_state_t *state, struct Generic_Headers_uint5bstr *result);
static bool decode_repeated_Generic_Headers_uint6bstr(zcbor_state_t *state, struct Generic_Headers_uint6bstr *result);
static bool decode_Generic_Headers(zcbor_state_t *state, struct Generic_Headers_r *result);
static bool decode_values(zcbor_state_t *state, struct values_r *result);
static bool decode_repeated_header_map_label(zcbor_state_t *state, struct header_map_label *result);
static bool decode_header_map(zcbor_state_t *state, struct header_map *result);


static bool decode_repeated_Generic_Headers_uint1union(
		zcbor_state_t *state, struct Generic_Headers_uint1union_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (1))))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).Generic_Headers_uint1union_int)))) && (((*result).Generic_Headers_uint1union_choice = Generic_Headers_uint1union_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).Generic_Headers_uint1union_tstr)))) && (((*result).Generic_Headers_uint1union_choice = Generic_Headers_uint1union_tstr_c), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_label(
		zcbor_state_t *state, struct label_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).label_int)))) && (((*result).label_choice = label_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).label_tstr)))) && (((*result).label_choice = label_tstr_c), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_Generic_Headers_label_m_l(
		zcbor_state_t *state, struct Generic_Headers_label_m_l_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (2))))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 3, &(*result).Generic_Headers_label_m_l_label_m_count, (zcbor_decoder_t *)decode_label, state, (&(*result).Generic_Headers_label_m_l_label_m), sizeof(struct label_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_Generic_Headers_uint3union(
		zcbor_state_t *state, struct Generic_Headers_uint3union_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (3))))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_tstr_decode(state, (&(*result).Generic_Headers_uint3union_tstr)))) && (((*result).Generic_Headers_uint3union_choice = Generic_Headers_uint3union_tstr_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).Generic_Headers_uint3union_int)))) && (((*result).Generic_Headers_uint3union_choice = Generic_Headers_uint3union_int_c), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_Generic_Headers_uint4bstr(
		zcbor_state_t *state, struct Generic_Headers_uint4bstr *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_bstr_decode(state, (&(*result).Generic_Headers_uint4bstr)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_Generic_Headers_uint5bstr(
		zcbor_state_t *state, struct Generic_Headers_uint5bstr *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (5))))
	&& (zcbor_bstr_decode(state, (&(*result).Generic_Headers_uint5bstr)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_Generic_Headers_uint6bstr(
		zcbor_state_t *state, struct Generic_Headers_uint6bstr *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (6))))
	&& (zcbor_bstr_decode(state, (&(*result).Generic_Headers_uint6bstr)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_Generic_Headers(
		zcbor_state_t *state, struct Generic_Headers_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_present_decode(&((*result).Generic_Headers_uint1union_present), (zcbor_decoder_t *)decode_repeated_Generic_Headers_uint1union, state, (&(*result).Generic_Headers_uint1union))
	&& zcbor_present_decode(&((*result).Generic_Headers_label_m_l_present), (zcbor_decoder_t *)decode_repeated_Generic_Headers_label_m_l, state, (&(*result).Generic_Headers_label_m_l))
	&& zcbor_present_decode(&((*result).Generic_Headers_uint3union_present), (zcbor_decoder_t *)decode_repeated_Generic_Headers_uint3union, state, (&(*result).Generic_Headers_uint3union))
	&& zcbor_present_decode(&((*result).Generic_Headers_uint4bstr_present), (zcbor_decoder_t *)decode_repeated_Generic_Headers_uint4bstr, state, (&(*result).Generic_Headers_uint4bstr))
	&& zcbor_present_decode(&((*result).Generic_Headers_uint5bstr_present), (zcbor_decoder_t *)decode_repeated_Generic_Headers_uint5bstr, state, (&(*result).Generic_Headers_uint5bstr))
	&& zcbor_present_decode(&((*result).Generic_Headers_uint6bstr_present), (zcbor_decoder_t *)decode_repeated_Generic_Headers_uint6bstr, state, (&(*result).Generic_Headers_uint6bstr)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_values(
		zcbor_state_t *state, struct values_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).values_int)))) && (((*result).values_choice = values_int_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).values_bstr)))) && (((*result).values_choice = values_bstr_c), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_repeated_header_map_label(
		zcbor_state_t *state, struct header_map_label *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((decode_label(state, (&(*result).header_map_label_key))))
	&& (decode_values(state, (&(*result).header_map_label)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool decode_header_map(
		zcbor_state_t *state, struct header_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((((decode_Generic_Headers(state, (&(*result).header_map_Generic_Headers_m))))
	&& zcbor_multi_decode(0, 3, &(*result).header_map_label_count, (zcbor_decoder_t *)decode_repeated_header_map_label, state, (&(*result).header_map_label), sizeof(struct header_map_label))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_header_map(
		const uint8_t *payload, size_t payload_len,
		struct header_map *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_header_map, sizeof(states) / sizeof(zcbor_state_t), 1);
}
