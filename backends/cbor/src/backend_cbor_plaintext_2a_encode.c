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
#include "backend_cbor_plaintext_2a_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_ead_x(zcbor_state_t *state, const struct ead_x *input);
static bool encode_ead(zcbor_state_t *state, const struct ead *input);
static bool encode_plaintext_2a(zcbor_state_t *state, const struct plaintext_2a *input);


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

static bool encode_ead(
		zcbor_state_t *state, const struct ead *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_encode_minmax(1, 3, &(*input).ead_count, (zcbor_encoder_t *)encode_ead_x, state, (&(*input).ead), sizeof(struct ead_x)));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_plaintext_2a(
		zcbor_state_t *state, const struct plaintext_2a *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((((*input).plaintext_2a_C_R_choice == plaintext_2a_C_R_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).plaintext_2a_C_R_bstr))))
	: (((*input).plaintext_2a_C_R_choice == plaintext_2a_C_R_int_c) ? (((((*input).plaintext_2a_C_R_int >= -24)
	&& ((*input).plaintext_2a_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input).plaintext_2a_C_R_int))))
	: false)))
	&& (!(*input).plaintext_2a_ead_m_present || encode_ead(state, (&(*input).plaintext_2a_ead_m))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_plaintext_2a(
		uint8_t *payload, size_t payload_len,
		const struct plaintext_2a *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_plaintext_2a, sizeof(states) / sizeof(zcbor_state_t), 7);
}
