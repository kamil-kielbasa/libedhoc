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
#include "backend_cbor_plaintext_3a_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_Generic_Headers_uint1union(zcbor_state_t *state, const struct Generic_Headers_uint1union_r *input);
static bool encode_label(zcbor_state_t *state, const struct label_r *input);
static bool encode_repeated_Generic_Headers_label_m_l(zcbor_state_t *state, const struct Generic_Headers_label_m_l_r *input);
static bool encode_repeated_Generic_Headers_uint3union(zcbor_state_t *state, const struct Generic_Headers_uint3union_r *input);
static bool encode_repeated_Generic_Headers_uint4bstr(zcbor_state_t *state, const struct Generic_Headers_uint4bstr *input);
static bool encode_repeated_Generic_Headers_uint5bstr(zcbor_state_t *state, const struct Generic_Headers_uint5bstr *input);
static bool encode_repeated_Generic_Headers_uint6bstr(zcbor_state_t *state, const struct Generic_Headers_uint6bstr *input);
static bool encode_Generic_Headers(zcbor_state_t *state, const struct Generic_Headers_r *input);
static bool encode_values(zcbor_state_t *state, const struct values_r *input);
static bool encode_repeated_header_map_label(zcbor_state_t *state, const struct header_map_label *input);
static bool encode_header_map(zcbor_state_t *state, const struct header_map *input);
static bool encode_plaintext_3a(zcbor_state_t *state, const struct plaintext_3a *input);


static bool encode_repeated_Generic_Headers_uint1union(
		zcbor_state_t *state, const struct Generic_Headers_uint1union_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (1))))
	&& (((*input).Generic_Headers_uint1union_choice == Generic_Headers_uint1union_int_c) ? ((zcbor_int32_encode(state, (&(*input).Generic_Headers_uint1union_int))))
	: (((*input).Generic_Headers_uint1union_choice == Generic_Headers_uint1union_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).Generic_Headers_uint1union_tstr))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_label(
		zcbor_state_t *state, const struct label_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).label_choice == label_int_c) ? ((zcbor_int32_encode(state, (&(*input).label_int))))
	: (((*input).label_choice == label_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).label_tstr))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_Generic_Headers_label_m_l(
		zcbor_state_t *state, const struct Generic_Headers_label_m_l_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (2))))
	&& (zcbor_list_start_encode(state, 3) && ((zcbor_multi_encode_minmax(1, 3, &(*input).Generic_Headers_label_m_l_label_m_count, (zcbor_encoder_t *)encode_label, state, (&(*input).Generic_Headers_label_m_l_label_m), sizeof(struct label_r))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_Generic_Headers_uint3union(
		zcbor_state_t *state, const struct Generic_Headers_uint3union_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (3))))
	&& (((*input).Generic_Headers_uint3union_choice == Generic_Headers_uint3union_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).Generic_Headers_uint3union_tstr))))
	: (((*input).Generic_Headers_uint3union_choice == Generic_Headers_uint3union_int_c) ? ((zcbor_int32_encode(state, (&(*input).Generic_Headers_uint3union_int))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_Generic_Headers_uint4bstr(
		zcbor_state_t *state, const struct Generic_Headers_uint4bstr *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (zcbor_bstr_encode(state, (&(*input).Generic_Headers_uint4bstr)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_Generic_Headers_uint5bstr(
		zcbor_state_t *state, const struct Generic_Headers_uint5bstr *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (5))))
	&& (zcbor_bstr_encode(state, (&(*input).Generic_Headers_uint5bstr)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_Generic_Headers_uint6bstr(
		zcbor_state_t *state, const struct Generic_Headers_uint6bstr *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (6))))
	&& (zcbor_bstr_encode(state, (&(*input).Generic_Headers_uint6bstr)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_Generic_Headers(
		zcbor_state_t *state, const struct Generic_Headers_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((!(*input).Generic_Headers_uint1union_present || encode_repeated_Generic_Headers_uint1union(state, (&(*input).Generic_Headers_uint1union)))
	&& (!(*input).Generic_Headers_label_m_l_present || encode_repeated_Generic_Headers_label_m_l(state, (&(*input).Generic_Headers_label_m_l)))
	&& (!(*input).Generic_Headers_uint3union_present || encode_repeated_Generic_Headers_uint3union(state, (&(*input).Generic_Headers_uint3union)))
	&& (!(*input).Generic_Headers_uint4bstr_present || encode_repeated_Generic_Headers_uint4bstr(state, (&(*input).Generic_Headers_uint4bstr)))
	&& (!(*input).Generic_Headers_uint5bstr_present || encode_repeated_Generic_Headers_uint5bstr(state, (&(*input).Generic_Headers_uint5bstr)))
	&& (!(*input).Generic_Headers_uint6bstr_present || encode_repeated_Generic_Headers_uint6bstr(state, (&(*input).Generic_Headers_uint6bstr))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_values(
		zcbor_state_t *state, const struct values_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).values_choice == values_int_c) ? ((zcbor_int32_encode(state, (&(*input).values_int))))
	: (((*input).values_choice == values_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).values_bstr))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_header_map_label(
		zcbor_state_t *state, const struct header_map_label *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((encode_label(state, (&(*input).header_map_label_key))))
	&& (encode_values(state, (&(*input).header_map_label)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_header_map(
		zcbor_state_t *state, const struct header_map *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 9) && ((((encode_Generic_Headers(state, (&(*input).header_map_Generic_Headers_m))))
	&& zcbor_multi_encode_minmax(0, 3, &(*input).header_map_label_count, (zcbor_encoder_t *)encode_repeated_header_map_label, state, (&(*input).header_map_label), sizeof(struct header_map_label))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 9))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_plaintext_3a(
		zcbor_state_t *state, const struct plaintext_3a *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((((*input).plaintext_3a_ID_CRED_PSK_choice == plaintext_3a_ID_CRED_PSK_header_map_m_c) ? ((encode_header_map(state, (&(*input).plaintext_3a_ID_CRED_PSK_header_map_m))))
	: (((*input).plaintext_3a_ID_CRED_PSK_choice == plaintext_3a_ID_CRED_PSK_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).plaintext_3a_ID_CRED_PSK_bstr))))
	: (((*input).plaintext_3a_ID_CRED_PSK_choice == plaintext_3a_ID_CRED_PSK_int_c) ? (((((*input).plaintext_3a_ID_CRED_PSK_int >= -24)
	&& ((*input).plaintext_3a_ID_CRED_PSK_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input).plaintext_3a_ID_CRED_PSK_int))))
	: false))))
	&& ((zcbor_bstr_encode(state, (&(*input).plaintext_3a_CIPHERTEXT_3B)))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_plaintext_3a(
		uint8_t *payload, size_t payload_len,
		const struct plaintext_3a *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_plaintext_3a, sizeof(states) / sizeof(zcbor_state_t), 2);
}
