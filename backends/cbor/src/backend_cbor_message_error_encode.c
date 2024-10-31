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
#include "backend_cbor_message_error_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_suites(zcbor_state_t *state, const struct suites_r *input);
static bool encode_repeated_message_error_ERR_INFO(zcbor_state_t *state, const struct message_error_ERR_INFO_r *input);
static bool encode_message_error(zcbor_state_t *state, const struct message_error *input);


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

static bool encode_repeated_message_error_ERR_INFO(
		zcbor_state_t *state, const struct message_error_ERR_INFO_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).message_error_ERR_INFO_choice == message_error_ERR_INFO_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).message_error_ERR_INFO_tstr))))
	: (((*input).message_error_ERR_INFO_choice == message_error_ERR_INFO_suites_m_c) ? ((encode_suites(state, (&(*input).message_error_ERR_INFO_suites_m))))
	: (((*input).message_error_ERR_INFO_choice == message_error_ERR_INFO_bool_c) ? ((zcbor_bool_put(state, (true))))
	: false)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_message_error(
		zcbor_state_t *state, const struct message_error *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input).message_error_ERR_CODE))))
	&& (!(*input).message_error_ERR_INFO_present || encode_repeated_message_error_ERR_INFO(state, (&(*input).message_error_ERR_INFO))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_message_error(
		uint8_t *payload, size_t payload_len,
		const struct message_error *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_message_error, sizeof(states) / sizeof(zcbor_state_t), 2);
}
