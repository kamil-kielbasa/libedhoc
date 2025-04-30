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
#include "backend_cbor_plaintext_2b_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_ead_y(zcbor_state_t *state, const struct ead_y *input);
static bool encode_EAD_2(zcbor_state_t *state, const struct EAD_2 *input);
static bool encode_plaintext_2b(zcbor_state_t *state, const struct plaintext_2b *input);


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

static bool encode_plaintext_2b(
		zcbor_state_t *state, const struct plaintext_2b *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((((*input).plaintext_2b_C_R_choice == plaintext_2b_C_R_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).plaintext_2b_C_R_bstr))))
	: (((*input).plaintext_2b_C_R_choice == plaintext_2b_C_R_int_c) ? (((((*input).plaintext_2b_C_R_int >= -24)
	&& ((*input).plaintext_2b_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input).plaintext_2b_C_R_int))))
	: false)))
	&& (!(*input).plaintext_2b_EAD_2_m_present || encode_EAD_2(state, (&(*input).plaintext_2b_EAD_2_m))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_plaintext_2b(
		uint8_t *payload, size_t payload_len,
		const struct plaintext_2b *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_plaintext_2b, sizeof(states) / sizeof(zcbor_state_t), 7);
}
