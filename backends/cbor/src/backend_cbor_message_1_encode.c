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
#include "backend_cbor_message_1_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_suites(zcbor_state_t *state, const struct suites_r *input);
static bool encode_ead_x(zcbor_state_t *state, const struct ead_x *input);
static bool encode_EAD_1(zcbor_state_t *state, const struct EAD_1 *input);
static bool encode_message_1(zcbor_state_t *state, const struct message_1 *input);


static bool encode_suites(
		zcbor_state_t *state, const struct suites_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).suites_choice == suites_int_l_c) ? ((zcbor_list_start_encode(state, 3) && ((zcbor_multi_encode_minmax(2, 3, &(*input).suites_int_l_int_count, (zcbor_encoder_t *)zcbor_int32_encode, state, (&(*input).suites_int_l_int), sizeof(int32_t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3)))
	: (((*input).suites_choice == suites_int_c) ? ((zcbor_int32_encode(state, (&(*input).suites_int))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_ead_x(
		zcbor_state_t *state, const struct ead_x *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input).ead_x_ead_label))))
	&& (!(*input).ead_x_ead_value_present || zcbor_bstr_encode(state, (&(*input).ead_x_ead_value))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_EAD_1(
		zcbor_state_t *state, const struct EAD_1 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_encode_minmax(1, 3, &(*input).EAD_1_count, (zcbor_encoder_t *)encode_ead_x, state, (&(*input).EAD_1), sizeof(struct ead_x)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_message_1(
		zcbor_state_t *state, const struct message_1 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input).message_1_METHOD))))
	&& ((encode_suites(state, (&(*input).message_1_SUITES_I))))
	&& ((zcbor_bstr_encode(state, (&(*input).message_1_G_X))))
	&& ((((*input).message_1_C_I_choice == message_1_C_I_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).message_1_C_I_bstr))))
	: (((*input).message_1_C_I_choice == message_1_C_I_int_c) ? (((((*input).message_1_C_I_int >= -24)
	&& ((*input).message_1_C_I_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input).message_1_C_I_int))))
	: false)))
	&& (!(*input).message_1_EAD_1_m_present || encode_EAD_1(state, (&(*input).message_1_EAD_1_m))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_message_1(
		uint8_t *payload, size_t payload_len,
		const struct message_1 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_message_1, sizeof(states) / sizeof(zcbor_state_t), 10);
}
